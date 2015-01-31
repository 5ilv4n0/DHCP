from time import time
from json import dumps
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








class Option_Type:
	PAD						= 0
	SUBNET_MASK				= 1
	ROUTER					= 3
	DNS_SERVER				= 6
	HOSTNAME 				= 12
	DOMAIN_NAME				= 15
	MTU						= 26
	BROADCAST				= 28
	STATIC_ROUTING_TABLE 	= 33
	NTP_SERVER				= 42
	REQUESTED_IP			= 50
	IP_LEASE_TIME			= 51
	OPTION_OVERLOAD         = 52
	MSG_TYPE 				= 53
	SERVER_ID				= 54
	PARAM_LIST				= 55
	MAX_MSG_SIZE 			= 57
	RENEW_TIME_VALUE		= 58
	REBINDING_TIME_VALUE	= 59
	CLASS_ID				= 60
	END						= 255

class Message_Type:
	DHCPDiscover 	= 1
	DHCPOffer 		= 2
	DHCPRequest		= 3
	DHCPDecline		= 4
	DHCPAck			= 5
	DHCPNak			= 6
	DHCPRelease 	= 7
	DHCPInform		= 8

class Packet_Type:
    RESPONSE = 1
    REPLY = 2




class DHCP_Packet_Options(list):
    PAD						= 0
    SUBNET_MASK				= 1
    TIME_OFFSET             = 2
    ROUTER					= 3
    TIME_SERVER             = 4
    NAME_SERVER             = 5
    DNS_SERVER				= 6
    LOG_SERVER              = 7
    QUOTE_SERVER            = 8
    LPR_SERVER              = 9
    IMPRESS_SERVER          = 10
    RES_LOC_SERVER          = 11
    HOSTNAME 				= 12
    BOOT_FILE_SIZE          = 13
    MERIT_DUMP_FILE         = 14
    DOMAIN_NAME				= 15
    SWAP_SERVER             = 16
    ROOT_PATH               = 17
    EXT_PATH                = 18
    IP_FORWARD              = 19
    NON_LOC_SOURCE_ROUTING  = 20
    POLICY_FILTER           = 21
    MAX_DATA_REAS_SIZE      = 22
    DEFAULT_IP_TTL          = 23
    PATH_MTU_AGING_TIMEOUT  = 24
    PATH_MTU_PLATEAU_TABLE  = 25
    MTU						= 26
    ALL_SUBNETS_LOCAL       = 27
    BROADCAST				= 28
    PERFORM_MASK_DISCOVERY  = 29
    MARK_SUPPLIER           = 30
    PERFORM_ROUTER_DISCOVERY= 31
    STATIC_ROUTING_TABLE 	= 33
    NTP_SERVER				= 42
    REQUESTED_IP			= 50
    IP_LEASE_TIME			= 51
    OPTION_OVERLOAD         = 52
    MESSAGE_TYPE 			= 53
    SERVER_ID				= 54
    PARAMETER_LIST			= 55
    MAX_MESSAGE_SIZE		= 57
    RENEW_TIME_VALUE		= 58
    REBINDING_TIME_VALUE	= 59
    CLASS_ID				= 60
    END						= 255

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
    	33: 'STATIC_ROUTING_TABLE',
    	42: 'NTP_SERVER',
    	50: 'REQUESTED_IP',
    	51: 'IP_LEASE_TIME',
    	52: 'OPTION_OVERLOAD',
    	53: 'MESSAGE_TYPE',
    	54: 'SERVER_ID',
    	55: 'PARAMETER_LIST',
    	57: 'MAX_MESSAGE_SIZE',
    	58: 'RENEW_TIME_VALUE',
    	59: 'REBINDING_TIME_VALUE',
    	60: 'CLASS_ID',
        255:'END'
    }

    def __init__(self, packet, offset=240):
        #for char in packet[240:]:
        #   self.append(ord(char))

        data = [
            53,1,1,
            2,4,1,2,3,4,
            1,4,255,255,0,0,
            54,4,10,10,10,2,
            28,4,10,10,255,255,
            3,4,10,10,0,1,
            6,8,8,8,8,8,8,8,4,4,
            60,4,44,88,3,7,
            4,4,123,123,232,3,
            5,4,10,10,0,1,
            7,4,7,7,7,7,
            255
        ]
        for d in data:
            self.append(d)

        self.options = self.__read_options()
        print dumps(self.options, indent=4)



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
            ]
            INTEGER_OPTIONS = [
                self.BOOT_FILE_SIZE,
                self.CLASS_ID,
                self.TIME_OFFSET,
                self.MAX_DATA_REAS_SIZE,
                self.PATH_MTU_AGING_TIMEOUT,
            ]
            BYTE_OPTIONS = [
                self.MESSAGE_TYPE,
                self.DEFAULT_IP_TTL,
            ]
            STRING_OPTIONS = [
                self.HOSTNAME,
                self.MERIT_DUMP_FILE,
                self.DOMAIN_NAME,
                self.ROOT_PATH,
                self.EXT_PATH,
            ]
            BOOLEAN_OPTIONS = [
                self.IP_FORWARD,
                self.NON_LOC_SOURCE_ROUTING,
                self.ALL_SUBNETS_LOCAL,
                self.PERFORM_MASK_DISCOVERY,
                self.MARK_SUPPLIER,
                self.PERFORM_ROUTER_DISCOVERY,
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

            if option_type == self.POLICY_FILTER:
                option_data = self.__read_ip_and_masks(option_data)

            if option_type == self.PATH_MTU_PLATEAU_TABLE:
                option_data = self.__read_mtu_plateau_table(option_data)

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

    def __read_mtu_plateau_table(self, option_data):
        set_count = len(option_data) / 2
        outlist = []
        for addr_id in range(set_count):
            data = option_data[addr_id*2:(addr_id*2)+2]
            data = self.__read_int(data)
            outlist.append(data)
        return outlist





class DHCP_Packet(list):
    def __init__(self, data):
        for char in data:
            self.append(char)
        self.options = DHCP_Packet_Options(self)
        print
        print self.options

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
    def boot_file_name(self, file_path='pxelinux.0'):
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
        return ''.join(self)


from random import randint

data = ''
for i in range(512):
    data += chr(randint(0,255))

p = DHCP_Packet(data)
