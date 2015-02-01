#!/usr/bin/env python
# -*- coding: utf-8 -*-

from time import time
from json import dumps
import socket, binascii, IN, thread
from sys import exit

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

	@property
	def mac_addresses(self):
		return self.__leases.keys()

	@property
	def leases(self):
		return self.__leases

    def __str__(self):
        out_string = ''
        for mac in self.__leases.keys():
            lease = self.__leases[mac]
            out_string += lease.mac + ' => ' + lease.ip + '\n'
        return out_string





class DHCP_Packet_Options(list):
    PAD						    = 0
    SUBNET_MASK				    = 1
    TIME_OFFSET                 = 2
    ROUTER			   	       	= 3
    TIME_SERVER                 = 4
    NAME_SERVER                 = 5
    DNS_SERVER		    		= 6
    LOG_SERVER                  = 7
    QUOTE_SERVER                = 8
    LPR_SERVER                  = 9
    IMPRESS_SERVER              = 10
    RES_LOC_SERVER              = 11
    HOSTNAME 		 		    = 12
    BOOT_FILE_SIZE              = 13
    MERIT_DUMP_FILE             = 14
    DOMAIN_NAME				    = 15
    SWAP_SERVER                 = 16
    ROOT_PATH                   = 17
    EXT_PATH                    = 18
    IP_FORWARD                  = 19
    NON_LOC_SOURCE_ROUTING      = 20
    POLICY_FILTER               = 21
    MAX_DATA_REAS_SIZE          = 22
    DEFAULT_IP_TTL              = 23
    PATH_MTU_AGING_TIMEOUT      = 24
    PATH_MTU_PLATEAU_TABLE      = 25
    MTU						    = 26
    ALL_SUBNETS_LOCAL           = 27
    BROADCAST				    = 28
    PERFORM_MASK_DISCOVERY      = 29
    MARK_SUPPLIER               = 30
    PERFORM_ROUTER_DISCOVERY    = 31
    ROUTER_SOLIC_ADDRESS        = 32
    STATIC_ROUTING_TABLE 	    = 33
    TRAILER_ENCAPSULATION       = 34
    ARP_CACHE_TIMEOUT           = 35
    ETHERNET_ENCAPSULATION      = 36
    TCP_DEFAULT_TTL             = 37
    TCP_KEEPALIVE_INTERVAL      = 38
    TCP_KEEPALIVE_GARBAGE       = 39
    NETWORK_INFO_SERVICE_DOMAIN = 40
    NETWORK_INFO_SERVERS        = 41
    NTP_SERVERS                 = 42
    VENDOR_SPECIFIC_INFORMATION = 43 #NOT FULLY IMPLEMENTED!
    NETBIOS_TCP_IP_NAME_SERVERS = 44
    NETBIOS_TCP_IP_DD_SERVERS   = 45
    NETBIOS_TCP_IP_NODE_TYPE    = 46
    NETBIOS_TCP_IP_SCOPE        = 47
    XWINDOW_SYSTEM_FONT_SERVERS = 48
    DHCP_OPT_BOOTP_VENDOR_EXTENTIONS = 49
    REQUESTED_IP		      	= 50
    IP_LEASE_TIME	      		= 51
    OPTION_OVERLOAD             = 52
    MESSAGE_TYPE 			    = 53
    SERVER_ID                   = 54
    PARAMETER_LIST              = 55
    MESSAGE                     = 56
    MAX_MESSAGE_SIZE            = 57
    RENEWAL_T1_TIME_VALUE       = 58
    REBINDING_T2_TIME_VALUE     = 59
    VENDOR_CLASS_ID             = 60
    CLIENT_ID                   = 61
    NET_INFO_SERVICE_PLUS_DOMAIN = 64
    NET_INFO_SERVICE_PLUS_SERVERS = 65
    TFTP_SERVER_NAME            = 66
    BOOTFILE_NAME               = 67
    MOBILE_IP_HOME_AGENT        = 68
    SMTP_SERVERS                = 69
    POP3_SERVERS                = 70
    NNTP_SERVERS                = 71
    DEFAULT_WWW_SERVERS         = 72
    DEFAULT_FINGER_SERVERS      = 73
    DEFAULT_IRC_SERVERS         = 74
    STREETTALK_SERVERS          = 75
    STREETTALK_DA_SERVERS       = 76
    END                         = 255

    OPTION_NAME = {
        0:  'PAD',
        1:  'SUBNET_MASK',
        2:  'TIME_OFFSET',
	    3:  'ROUTER',
        4:  'TIME_SERVER',
        5:  'NAME_SERVER',
	    6:  'DNS_SERVER',
        7:  'LOG_SERVER',
        8:  'QUOTE_SERVER',
        9:  'LPR_SERVER',
        10: 'IMPRESS_SERVER',
        11: 'RES_LOC_SERVER',
    	12: 'HOSTNAME',
        13: 'BOOT_FILE_SIZE',
        14: 'MERIT_DUMP_FILE',
    	15: 'DOMAIN_NAME',
        16: 'SWAP_SERVER',
        17: 'ROOT_PATH',
        18: 'EXT_PATH',
        19: 'IP_FORWARD',
        20: 'NON_LOC_SOURCE_ROUTING',
        21: 'POLICY_FILTER',
        22: 'MAX_DATA_REAS_SIZE',
        23: 'DEFAULT_IP_TTL',
        24: 'PATH_MTU_AGING_TIMEOUT',
        25: 'PATH_MTU_PLATEAU_TABLE',
    	26: 'MTU',
        27: 'ALL_SUBNETS_LOCAL',
    	28: 'BROADCAST',
        29: 'PERFORM_MASK_DISCOVERY',
        30: 'MARK_SUPPLIER',
        31: 'PERFORM_ROUTER_DISCOVERY',
        32: 'ROUTER_SOLIC_ADDRESS',
    	33: 'STATIC_ROUTING_TABLE',
        34: 'TRAILER_ENCAPSULATION',
        35: 'ARP_CACHE_TIMEOUT',
        36: 'ETHERNET_ENCAPSULATION',
        37: 'TCP_DEFAULT_TTL',
        38: 'TCP_KEEPALIVE_INTERVAL',
        39: 'TCP_KEEPALIVE_GARBAGE',
        40: 'NETWORK_INFO_SERVICE_DOMAIN',
        41: 'NETWORK_INFO_SERVERS',
    	42: 'NTP_SERVERS',
        43: 'VENDOR_SPECIFIC_INFORMATION',
        44: 'NETBIOS_TCP_IP_NAME_SERVERS',
        45: 'NETBIOS_TCP_IP_DD_SERVERS',
        46: 'NETBIOS_TCP_IP_NODE_TYPE',
        47: 'NETBIOS_TCP_IP_SCOPE',
        48: 'XWINDOW_SYSTEM_FONT_SERVERS',
        49: 'DHCP_OPT_BOOTP_VENDOR_EXTENTIONS',
    	50: 'REQUESTED_IP',
    	51: 'IP_LEASE_TIME',
    	52: 'OPTION_OVERLOAD',
    	53: 'MESSAGE_TYPE',
    	54: 'SERVER_ID',
    	55: 'PARAMETER_LIST',
        56: 'MESSAGE',
    	57: 'MAX_MESSAGE_SIZE',
    	58: 'RENEWAL_T1_TIME_VALUE',
    	59: 'REBINDING_T2_TIME_VALUE',
    	60: 'VENDOR_CLASS_ID',
        61: 'CLIENT_ID',
        64: 'NET_INFO_SERVICE_PLUS_DOMAIN',
        65: 'NET_INFO_SERVICE_PLUS_SERVERS',
        66: 'TFTP_SERVER_NAME',
        67: 'BOOTFILE_NAME',
        68: 'MOBILE_IP_HOME_AGENT',
        69: 'SMTP_SERVERS',
        70: 'POP3_SERVERS',
        71: 'NNTP_SERVERS',
        72: 'DEFAULT_WWW_SERVERS',
        73: 'DEFAULT_FINGER_SERVERS',
        74: 'DEFAULT_IRC_SERVERS',
        75: 'STREETTALK_SERVERS',
        76: 'STREETTALK_DA_SERVERS',
        255:'END'
    }

    def __init__(self, packet, offset=240):
        for char in packet[240:]:
           self.append(ord(char))

        self.options = self.__read_options()
        self.sending_options = []
        print dumps(self.options, indent=4)

    def add_option(self, option_type, option_data):
        print option_type, option_data, type(option_data)


        if "'int'" in str(type(option_data)):
        	self.sending_options.append(chr(option_type))
        	if option_type == self.MESSAGE_TYPE:
        		option_length = 1
        	if option_type == self.MTU:
        		option_length = 2
        	LENGTH_4_TYPES = [
        		self.IP_LEASE_TIME,
        		self.RENEWAL_T1_TIME_VALUE,
        		self.REBINDING_T2_TIME_VALUE
			]
        	if option_type in LENGTH_4_TYPES:
        		option_length = 4
        	self.sending_options.append(chr(option_length))
        	option_data_hex = hex(option_data)[2:].rjust(option_length * 2,'0')
        	for i in range(option_length):
        		self.sending_options.append(chr(int(option_data_hex[i*2:(i*2)+2],16)))

        if "'str'" in str(type(option_data)):
        	self.sending_options.append(chr(option_type))
        	self.sending_options.append(chr(len(option_data)))
			for char in option_data:
				self.sending_options.append(char)

        if "'list'" in str(type(option_data)):
			entry_type = str(type(option_data[0]))
			if  "'str'" in entry_type:
				length = 0
				for entry in option_data:
					length += len()

        	self.sending_options.append(chr(option_type))
        	self.sending_options.append(chr(len(option_data)))
			for char in option_data:
				self.sending_options.append(char)



    def __read_options(self):
        options = {}
        offset=0
        while True:
            option_type = self[offset]
            if option_type == self.END:
                break
            option_length = self[offset+1]
            data_start = offset + 2
            data_end = offset+2+option_length
            option_data = self[data_start:data_end]

            SINGLE_IP_OPTIONS = [
                self.SUBNET_MASK,
                self.BROADCAST,
                self.SERVER_ID,
                self.ROUTER,
                self.SWAP_SERVER,
                self.ROUTER_SOLIC_ADDRESS,
                self.REQUESTED_IP
            ]
            MULTI_IP_OPTIONS = [
                self.DNS_SERVER,
                self.TIME_SERVER,
                self.LOG_SERVER,
                self.NAME_SERVER,
                self.QUOTE_SERVER,
                self.LPR_SERVER,
                self.IMPRESS_SERVER,
                self.RES_LOC_SERVER,
                self.NETWORK_INFO_SERVERS,
                self.NTP_SERVERS,
                self.NETBIOS_TCP_IP_NAME_SERVERS,
                self.NETBIOS_TCP_IP_DD_SERVERS,
                self.XWINDOW_SYSTEM_FONT_SERVERS,
                self.DHCP_OPT_BOOTP_VENDOR_EXTENTIONS,
                self.NET_INFO_SERVICE_PLUS_SERVERS,
                self.MOBILE_IP_HOME_AGENT,
                self.SMTP_SERVERS,
                self.POP3_SERVERS,
                self.NNTP_SERVERS,
                self.DEFAULT_WWW_SERVERS,
                self.DEFAULT_FINGER_SERVERS,
                self.DEFAULT_IRC_SERVERS,
                self.STREETTALK_SERVERS,
                self.STREETTALK_DA_SERVERS
            ]
            INTEGER_OPTIONS = [
                self.BOOT_FILE_SIZE,
                self.TIME_OFFSET,
                self.MAX_DATA_REAS_SIZE,
                self.PATH_MTU_AGING_TIMEOUT,
                self.ARP_CACHE_TIMEOUT,
                self.TCP_KEEPALIVE_INTERVAL,
                self.IP_LEASE_TIME,
                self.MAX_MESSAGE_SIZE,
                self.RENEWAL_T1_TIME_VALUE,
                self.REBINDING_T2_TIME_VALUE,
            ]
            BYTE_OPTIONS = [
                self.MESSAGE_TYPE,
                self.DEFAULT_IP_TTL,
                self.TCP_DEFAULT_TTL,
                self.NETBIOS_TCP_IP_NODE_TYPE,
                self.OPTION_OVERLOAD
            ]
            STRING_OPTIONS = [
                self.HOSTNAME,
                self.MERIT_DUMP_FILE,
                self.DOMAIN_NAME,
                self.ROOT_PATH,
                self.EXT_PATH,
                self.NETWORK_INFO_SERVICE_DOMAIN,
                self.VENDOR_SPECIFIC_INFORMATION,
                self.NETBIOS_TCP_IP_SCOPE,
                self.NET_INFO_SERVICE_PLUS_DOMAIN,
                self.TFTP_SERVER_NAME,
                self.BOOTFILE_NAME,
                self.MESSAGE,
				self.VENDOR_CLASS_ID
            ]
            BOOLEAN_OPTIONS = [
                self.IP_FORWARD,
                self.NON_LOC_SOURCE_ROUTING,
                self.ALL_SUBNETS_LOCAL,
                self.PERFORM_MASK_DISCOVERY,
                self.MARK_SUPPLIER,
                self.PERFORM_ROUTER_DISCOVERY,
                self.TRAILER_ENCAPSULATION,
                self.ETHERNET_ENCAPSULATION,
                self.TCP_KEEPALIVE_GARBAGE
            ]
            BYTE_LIST_OPTIONS = [
                self.CLIENT_ID
            ]

            if option_type in BOOLEAN_OPTIONS:
                option_data = self.__read_boolean(option_data)
            if option_type in SINGLE_IP_OPTIONS:
                ip_list = [str(option_data[0]), str(option_data[1]), str(option_data[2]), str(option_data[3])]
                option_data = self.__read_ip(option_data)
            if option_type in MULTI_IP_OPTIONS:
                option_data = self.__read_ips(option_data)
            if option_type in INTEGER_OPTIONS:
                option_data = self.__read_int(option_data)
            if option_type in BYTE_OPTIONS:
                option_data = self.__read_byte(option_data)
            if option_type in STRING_OPTIONS:
                option_data = self.__read_string(option_data)
            if option_type in BYTE_LIST_OPTIONS:
                option_data = self.__read_byte_list(option_data)

            if option_type == self.POLICY_FILTER:
                option_data = self.__read_ip_and_masks(option_data)

            if option_type == self.STATIC_ROUTING_TABLE:
                option_data = self.__read_static_routing_table(option_data)

            if option_type == self.PATH_MTU_PLATEAU_TABLE:
                option_data = self.__read_mtu_plateau_table(option_data)

            if option_type == self.PARAMETER_LIST:
                options['PARAMETER_LIST_BYTES'] = option_data
                option_data = self.__read_parameter_list(option_data)

            options[self.OPTION_NAME[option_type]] = option_data
            offset += 2+option_length
        return options

    def __read_boolean(self, option_data):
        byte = self.__read_byte(option_data)
        if byte == 1:
            return True
        return False
    def __read_byte(self, option_data):
        return option_data[0]
    def __read_ips(self, option_data):
        ip_list = []
        count_ips = len(option_data) / 4
        for ip_id in range(count_ips):
            ip_data = option_data[ip_id*4:(ip_id*4)+4]
            ip_list.append(self.__read_ip(ip_data))
        return ip_list
    def __read_ip(self, option_data):
        ip_list = [str(option_data[0]), str(option_data[1]), str(option_data[2]), str(option_data[3])]
        return '.'.join(ip_list)
    def __read_int(self, option_data):
        hex_string = ''
        for byte in option_data:
            hex_string += hex(byte)[2:].rjust(2,'0')
        return int(hex_string, 16)
    def __read_string(self, option_data):
        string = ''
        for byte in option_data:
        	string += chr(byte)
        return string

    def __read_ip_and_masks(self, option_data):
        option_data = self.__read_ips(option_data)
        set_count = len(option_data) / 2
        outlist = []
        for addr_id in range(set_count):
            data = option_data[addr_id*2:(addr_id*2)+2]
            print data
            outlist.append('/'.join(data))
        return outlist

    def __read_static_routing_table(self, option_data):
        option_data = self.__read_ips(option_data)
        set_count = len(option_data) / 2
        outlist = []
        for addr_id in range(set_count):
            data = option_data[addr_id*2:(addr_id*2)+2]
            print data
            outlist.append(':'.join(data))
        return outlist

    def __read_mtu_plateau_table(self, option_data):
        set_count = len(option_data) / 2
        outlist = []
        for addr_id in range(set_count):
            data = option_data[addr_id*2:(addr_id*2)+2]
            data = self.__read_int(data)
            outlist.append(data)
        return outlist

    def __read_byte_list(self, option_data): #SENSELESS^^
        return option_data

    def __read_parameter_list(self, option_data):
        out_list = []
        for parameter in option_data:
        	out_list.append(self.OPTION_NAME[parameter])
        return out_list

class DHCP_Packet(list):

    class Packet_Type:
        RESPONSE = 1
        REPLY = 2

    class Message_Type:
    	DHCPDiscover 	= 1
    	DHCPOffer 		= 2
    	DHCPRequest		= 3
    	DHCPDecline		= 4
    	DHCPAck			= 5
    	DHCPNak			= 6
    	DHCPRelease 	= 7
    	DHCPInform		= 8

    def __init__(self, data):
        for char in data:
            self.append(char)
        self.options = DHCP_Packet_Options(self)

    @property
    def packet_type(self):
        return ord(self[0])
    @packet_type.setter
    def packet_type(self, packet_type):
        self[0] = chr(packet_type)

    @property
    def hardware_address_type(self):
        return ord(self[1])
    @hardware_address_type.setter
    def hardware_address_type(self, hardware_address_type):
        self[1] = chr(hardware_address_type)

    @property
    def hardware_address_len(self):
        return ord(self[2])
    @hardware_address_len.setter
    def hardware_address_len(self, hardware_address_len):
        self[2] = chr(hardware_address_len)

    @property
    def hops(self):
        return ord(self[3])
    @hops.setter
    def hops(self, hops):
        self[3] = chr(hops)

    @property
    def transaction_id(self):
        transaction_id_intlist = [ord(self[4]), ord(self[5]), ord(self[6]), ord(self[7])]
        return self.__intlist_to_int(transaction_id_intlist)
    @transaction_id.setter
    def transaction_id(self, transaction_id):
        intlist = self.__int_to_intlist(transaction_id)
        chrlist = self.intlist_to_charlist(intlist)
        self[4] = chrlist[0]
        self[5] = chrlist[1]
        self[6] = chrlist[2]
        self[7] = chrlist[3]

    @property
    def secs(self):
        secs_intlist = [0, 0, ord(self[8]), ord(self[9])]
        return self.__intlist_to_int(secs_intlist)
    @secs.setter
    def secs(self, secs):
        intlist = self.__int_to_intlist(secs)
        chrlist = self.intlist_to_charlist(intlist)
        self[8] = chrlist[2]
        self[9] = chrlist[3]

    @property
    def flags(self):
        flags_intlist = [0, 0, ord(self[10]), ord(self[11])]
        return self.__intlist_to_int(flags_intlist)
    @flags.setter
    def flags(self, flags):
        intlist = self.__int_to_intlist(secs)
        chrlist = self.intlist_to_charlist(intlist)
        self[10] = chrlist[2]
        self[11] = chrlist[3]

    @property
    def current_client_ip(self):
        return self.__read_ip(12)
    @current_client_ip.setter
    def current_client_ip(self, client_ip='0.0.0.0'):
        self.__write_ip(client_ip, 12)

    @property
    def client_ip(self):
        return self.__read_ip(16)
    @client_ip.setter
    def client_ip(self, client_ip='0.0.0.0'):
        self.__write_ip(client_ip, 16)

    @property
    def server_ip(self):
        return self.__read_ip(20)
    @server_ip.setter
    def server_ip(self, server_ip='0.0.0.0'):
        self.__write_ip(server_ip, 20)

    @property
    def relay_agent_ip(self):
        return self.__read_ip(24)
    @relay_agent_ip.setter
    def relay_agent_ip(self, server_ip='0.0.0.0'):
        self.__write_ip(server_ip, 24)

    @property
    def client_hw_address(self):
        return self.__read_hw()
    @client_hw_address.setter
    def client_hw_address(self, hw='00:00:00:00:00:00'):
        self.__write_hw(hw)

    @property
    def server_host_name(self):
        out_string = ''
        for char in self.__read_string(44,64):
            if char == '\0':
                break
            out_string += char
        return out_string
    @server_host_name.setter
    def server_host_name(self, hostname):
        self.__write_string(hostname, 44, 64)

    @property
    def boot_file_name(self):
        out_string = ''
        for char in self.__read_string(108,128):
            if char == '\0':
                break
            out_string += char
        return out_string
    @boot_file_name.setter
    def boot_file_name(self, file_path='/pxelinux.0'):
        self.__write_string(hostname, 108, 128)

    @property
    def magic_cookie(self):
        magic_cookie_intlist = [ord(self[236]), ord(self[237]), ord(self[238]), ord(self[239])]
        return self.__intlist_to_int(magic_cookie_intlist)
    @magic_cookie.setter
    def magic_cookie(self, magic_cookie):
        intlist = self.__int_to_intlist(magic_cookie)
        chrlist = self.intlist_to_charlist(intlist)
        self[236] = chrlist[0]
        self[237] = chrlist[1]
        self[238] = chrlist[2]
        self[239] = chrlist[3]




    def __read_string(self, offset=0, length=1):
        chrlist = self[offset:offset+length]
        return ''.join(chrlist)

    def __write_string(self, string, offset=0, length=0):
        for char_id, char in enumerate(string):
            if char_id == length - 2:
                break
            self[offset+char_id] = char
        while not char_id == length - 1:
            self[offset+char_id+1] = '\0'
            char_id += 1

    def __read_hw(self, offset=28):
        hw = []
        hw_chrlist = self[offset:offset+16]
        for char in hw_chrlist:
            hw.append(hex(ord(char))[2:].rjust(2,'0'))
        hw_out = hw[:self.hardware_address_len]
        return ':'.join(hw_out)

    def __write_hw(self, hw, offset=28):
        hw_list = hw.split(':')
        hw_intlist = []
        for byte in hw_list:
            integer = int(byte, 16)
            hw_intlist.append(integer)
        for byte_id in range(self.hardware_address_len):
            try:
                self[offset+byte_id] = chr(hw_intlist[byte_id])
            except IndexError:
                self[offset+byte_id] = chr(0)

    def __read_ip(self, offset=0):
        ip_intlist = [ord(self[offset]), ord(self[offset+1]), ord(self[offset+2]), ord(self[offset+3])]
        ip_int = self.__intlist_to_int(ip_intlist)
        return Tools.int_to_ip(ip_int)

    def __write_ip(self, ip, offset=0):
        ip_int = Tools.ip_to_int(ip)
        intlist = self.__int_to_intlist(ip_int)
        chrlist = self.intlist_to_charlist(intlist)
        self[offset] = chrlist[0]
        self[offset+1] = chrlist[1]
        self[offset+2] = chrlist[2]
        self[offset+3] = chrlist[3]

    def __intlist_to_int(self, int_list=[0,0,0,0]):
        integer = 0
        integer += (int_list[0] * 16777216)
        integer += (int_list[1] * 65536)
        integer += (int_list[2] * 256)
        integer += int_list[3]
        return integer

    def intlist_to_charlist(self, int_list=[0,0,0,0]):
        return [chr(int_list[0]),chr(int_list[1]),chr(int_list[2]),chr(int_list[3])]

    def __int_to_intlist(self, integer=0):
        intlist = [0,0,0,0]
        integer_hex = hex(integer)[2:].rjust(8,'0')
        int_0 = int(integer_hex[:2],16)
        int_1 = int(integer_hex[2:4],16)
        int_2 = int(integer_hex[4:6],16)
        int_3 = int(integer_hex[6:8],16)
        intlist = [int_0, int_1, int_2, int_3]
        return intlist

    def __str__(self):
        return self.__packet_raw_output()

    def __packet_raw_output(self):
		string = ''
		raw_data = []
		string += '+-----------------+\n'
		for char in self:
			raw_data.append(hex(ord(char))[2:].rjust(2,'0'))
			c = 0
		for id, dat in enumerate(raw_data):
			if c == 0:
				string += '|'+ str(id).rjust(3,'0')+'|'
			string += dat + ' '
			c += 1
			if c == 4:
				c=0
				string += '|\n'
		string += '+-----------------+\n'
		return string

    def is_dhcp_discovery(self):
		if self.options.options['MESSAGE_TYPE'] == self.Message_Type.DHCPDiscover:
			return True
		return False

    def is_dhcp_request(self):
		if self.options.options['MESSAGE_TYPE'] == self.Message_Type.DHCPRequest:
			return True
		return False




config = {
	'interface': 'wlan0',
	'server_ip': '10.10.10.2',
	'netmask': '255.255.0.0',
	'gateway': '10.10.0.1',
	'dns': ['8.8.8.8','8.8.4.4'],
	'domain': 'silvano87.local',
	'ntp_server': 'de.pool.ntp.org',
	'range': ['10.10.10.50','10.10.10.100'],
	'default_lease_time': 120,
}

class DHCP_Server(object):
	def __init__(self, config):
		self.interface = config['interface']
		self.mtu = self.__get_mtu()
		self.port = 67
		self.server_ip = config['server_ip']
		self.netmask = config['netmask']
		self.gateway = config['gateway']
		self.dns = config['dns']
		self.domain = config['domain']
		self.ntp = config['ntp_server']
		self.range = config['range']
		self.default_lease_time = config['default_lease_time']
		self.leases = Leases(self.server_ip, self.netmask, ip_range=self.range)

        #self.dhcp_thread = thread.start_new_thread(self.run,(None,))

	def __delete_expired_leases(self):
		delete_ip_list = []
		for mac in self.leases.mac_addresses:
			lease = self.leases.leases[mac]
			if not lease.valid:
				delete_ip_list.append(lease.ip)
		for ip in delete_ip_list:
			self.leases.delete(ip)

	def __get_mtu(self):
		with open('/sys/class/net/'+self.interface+'/mtu') as mtu:
			mtu = mtu.read()
		return int(mtu)

	def run(self, nothing=None):
		if not hasattr(IN, 'SO_BINDTODEVICE'):
			IN.SO_BINDTODEVICE = 25  #http://stackoverflow.com/a/8437870/541038

		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.setsockopt(socket.SOL_SOCKET,IN.SO_BINDTODEVICE, self.interface+'\0') #experimental
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		s.bind(('', self.port))


		while True:
			try:
				message, addressf = s.recvfrom(8192)
				packet = DHCP_Packet(message)
				mac_address = packet.client_hw_address

				if packet.is_dhcp_discovery():
				 	lease = self.leases.exists_lease(mac_address)
				 	if lease == False:
				 		lease = self.leases.create(mac_address, time=self.default_lease_time)
				 		if lease == False:
				 			self.generate_Nak(lease, packet)


				 	else:
						self.generate_Offer(lease, packet)
				# 		self.send_Offer(s, packet, lease['ip'])
				# elif packet.is_dhcp_request():
				# 	lease = self.leases.exists_lease(mac_address)
				# 	if lease == False:
				# 		self.send_Nak(s, packet)
				# 	else:
				# 		self.send_Ack(s, packet, lease['ip'])
				# 		print 'LEASED:', lease['ip']


			except KeyboardInterrupt:
				exit()



	def generate_Offer(self, lease, packet):
		packet.packet_type = packet.Packet_Type.REPLY
		packet.client_ip = lease.ip
		packet.server_ip = self.server_ip
		packet.options.add_option(packet.options.MESSAGE_TYPE, packet.Message_Type.DHCPOffer)

		for requested_option_type in packet.options.options['PARAMETER_LIST_BYTES']:
			if requested_option_type == packet.options.SUBNET_MASK:
				packet.options.add_option(packet.options.SUBNET_MASK, self.netmask)
			elif requested_option_type == packet.options.ROUTER:
				packet.options.add_option(packet.options.ROUTER, self.gateway)
			elif requested_option_type == packet.options.DNS_SERVER:
				packet.options.add_option(packet.options.DNS_SERVER, self.dns)
			elif requested_option_type == packet.options.DOMAIN_NAME:
				packet.options.add_option(packet.options.DOMAIN_NAME, self.domain)
			elif requested_option_type == packet.options.MTU:
				packet.options.add_option(packet.options.MTU, self.mtu)
			elif requested_option_type == packet.options.BROADCAST:
				packet.options.add_option(packet.options.BROADCAST, Tools.broadcast_address_from(self.server_ip, self.netmask))
			elif requested_option_type == packet.options.SERVER_ID:
				packet.options.add_option(packet.options.SERVER_ID, self.server_ip)
			elif requested_option_type == packet.options.RENEWAL_T1_TIME_VALUE:
				packet.options.add_option(packet.options.RENEWAL_T1_TIME_VALUE, self.default_lease_time / 2)
			elif requested_option_type == packet.options.REBINDING_T2_TIME_VALUE:
				packet.options.add_option(packet.options.REBINDING_T2_TIME_VALUE, (self.default_lease_time / 4) * 3)
			elif requested_option_type == packet.options.IP_LEASE_TIME:
				packet.options.add_option(packet.options.IP_LEASE_TIME, self.default_lease_time)

		print packet.options.sending_options

		#data = packet.generate_dhcp_paket(Message_Type.DHCPNak, '0.0.0.0', self.server_ip)
		#if data:
		#	s.sendto(data,('<broadcast>',68)) ##################DHCPNack
		#	return True
		#return False

	def send_Offer(self, s, packet, ip_address):
		data = packet.generate_dhcp_paket(Message_Type.DHCPOffer, ip_address, self.server_ip)
		if data:
			s.sendto(data,('<broadcast>',68)) ##################DHCPNack
			return True
		return False

	def send_Ack(self, s, packet, ip_address):
		data = packet.generate_dhcp_paket(Message_Type.DHCPAck, ip_address, self.server_ip)
		if data:
			s.sendto(data,('<broadcast>',68)) ##################DHCPNack
			return True
		return False



dhcp = DHCP_Server(config)
dhcp.run()





#exit()
