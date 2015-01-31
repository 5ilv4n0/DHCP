from time import time
from json import dumps

class Lease(object):
    def __init__(self, **keyword_args):
        if not 'mac' in keyword_args.keys():
            self.mac = None
        else:
            self.mac = keyword_args['mac']

        if not 'ip' in keyword_args.keys():
            self.ip = None
        else:
            self.ip = keyword_args['ip']

        if not 'hostname' in keyword_args.keys():
            self.hostname = None
        else:
            self.hostname = keyword_args['hostname']

        if not 'time' in keyword_args.keys():
            self.time = 86400
        else:
            self.time = keyword_args['time']

        self.renew_times()

    def renew_times(self):
        self.create_time = int(time())
        self.lease_ends = self.create_time + self.time

    @property
    def valid(self):
        current_time = int(time())
        if self.ip == None or self.mac == None or current_time >= self.lease_ends:
            return False
        return True

    def __str__(self):
        return dumps(self.__dict__, indent=4)

class DHCPRangeError(Exception):
	pass

class ToolBox(object):
    def ip_to_int(self, ip_string):
        ip_list = ip_string.split('.')
        ip_list = [ int(ip_list[0]), int(ip_list[1]), int(ip_list[2]), int(ip_list[3]) ]
        ip = 0
        ip += ip_list[0] * 16777216
        ip += ip_list[1] * 65536
        ip += ip_list[2] * 256
        ip += ip_list[3]
        return ip

    def int_to_ip(self, ip_int):
        ip_hex = hex(ip_int)
        ip_hex = ip_hex[2:].rjust(8,'0')
        ip_0 = int(ip_hex[:2].rjust(2,'0'), 16)
        ip_1 = int(ip_hex[2:4].rjust(2,'0'), 16)
        ip_2 = int(ip_hex[4:6].rjust(2,'0'), 16)
        ip_3 = int(ip_hex[6:8].rjust(2,'0'), 16)
        ip_list = [str(ip_0), str(ip_1), str(ip_2), str(ip_3)]
        ip_string = '.'.join(ip_list)
        return ip_string

    def net_address_from(self, ip, netmask):
        ip_int = self.ip_to_int(ip)
        netmask_int = self.ip_to_int(netmask)
        net_ip_int = ip_int & netmask_int
        net_ip = self.int_to_ip(net_ip_int)
        return net_ip

    def broadcast_address_from(self, ip, netmask):
        ip_int = self.ip_to_int(ip)
        netmask_int = self.ip_to_int(netmask)
        net_ip_int = ip_int & netmask_int
        net_ip_bin = bin(net_ip_int)[2:].rjust(32,'0')
        netmask_bin = bin(netmask_int)[2:].rjust(32,'0')
        broadcast_bin = ''
        for bit_id in range(32):
            if net_ip_bin[bit_id] == netmask_bin[bit_id]:
                broadcast_bin += '1'
            else:
                broadcast_bin += '0'
        broadcast_int = int(broadcast_bin, 2)
        broadcast_ip = self.int_to_ip(broadcast_int)
        return broadcast_ip
Tools = ToolBox()

class Leases(object):
    def __init__(self, server_ip, netmask, ip_range=None, **keyword_args):
        self.server_ip = server_ip
        self.netmask = netmask
        self.net_address = Tools.net_address_from(server_ip, netmask)
        self.broadcast = Tools.broadcast_address_from(server_ip, netmask)
        if ip_range == None:
            ip_range = self.__generate_ip_range_by_network()
        self.range_from = ip_range[0]
        self.range_to = ip_range[1]
        self.range_int = self.__calculate_range()
        self.__used_ip_list = [self.server_ip]
        self.__leases = {}

    def __generate_ip_range_by_network(self):
        net_address_int = Tools.ip_to_int(self.net_address)
        broadcast_int = Tools.ip_to_int(self.broadcast)
        first_ip_int = net_address_int + 1
        last_ip_int = broadcast_int - 1
        first_ip = Tools.int_to_ip(first_ip_int)
        last_ip = Tools.int_to_ip(last_ip_int)
        ip_range = [first_ip, last_ip]
        return ip_range

    def __calculate_range(self):
        range_from_int = Tools.ip_to_int(self.range_from)
        range_to_int = Tools.ip_to_int(self.range_to)
        if range_from_int >= range_to_int:
            raise DHCPRangeError()
        return self.__generate_ip_range_int(range_from_int, range_to_int)

    def __generate_ip_range_int(self, from_ip, to_ip):
        ip_range_int_list = []
        for ip_int in xrange(from_ip, to_ip + 1):
            ip_range_int_list.append(ip_int)
        return ip_range_int_list

    def create(self, mac, **keyword_arg):
        if not 'hostname' in keyword_arg.keys():
            hostname = None
        else:
            hostname = keyword_arg['hostname']
        if not 'time' in keyword_arg.keys():
            lease_time = 3600
        else:
            lease_time = keyword_arg['time']
        if not 'ip' in keyword_arg.keys():
            ip = None
        else:
            ip = keyword_arg['ip']
        if not self.__exists_lease(mac):
            if ip == None:
                ip = self.__get_ip()
            if ip == False:
                return False
            if not self.__is_ip_in_network(ip):
                return False
            if not self.__is_ip_in_use(ip):
                self.__leases[mac] = Lease(mac=mac, ip=ip, hostname=hostname, time=lease_time)
                self.__used_ip_list.append(ip)
                return self.__leases[mac]
        else:
            if self.__leases[mac].valid:
                return self.get_ip(mac)
        return False

    def __exists_lease(self, mac):
        return mac in self.__leases.keys()

    def exists_lease(self, mac):
        if mac in self.__leases.keys():
            return self.__leases[mac]
        return False

    def __is_ip_in_use(self, ip):
        return ip in self.__used_ip_list

    def __is_ip_in_network(self, ip):
        net_address = Tools.ip_to_int(self.net_address)
        broadcast = Tools.ip_to_int(self.broadcast)
        ip = Tools.ip_to_int(ip)
        if ip > net_address and ip < broadcast:
            return True
        return False

    def __get_ip(self):
        for ip_int in self.range_int:
            ip = Tools.int_to_ip(ip_int)
            if not self.__is_ip_in_use(ip):
                return ip
        return False

    def get_ip(self, mac):
        try:
            return self.__leases[mac].ip
        except KeyError:
            return False

    def resolv_ip(self, ip):
        for mac in self.__leases.keys():
            if self.__leases[mac].ip == ip:
                return mac
        return False

    def delete(self, ip):
        try:
            ip_index = self.__used_ip_list.index(ip)
        except ValueError:
            return False
        mac = self.resolv_ip(ip)
        del self.__leases[mac]
        del self.__used_ip_list[ip_index]
        return True

    def __str__(self):
        out_string = ''
        for mac in self.__leases.keys():
            lease = self.__leases[mac]
            out_string += lease.mac + ' => ' + lease.ip + '\n'
        return out_string
