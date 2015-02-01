from json import dumps



class DHCP_Packet_Option(object):
    def __init__(self, typ, string):
        self.type = typ
        self.payload = []
        for char in string:
            self.payload.append(ord(char))
        self.length = len(self.payload)



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


    def __init__(self, packet=['\xff'], offset=240):
        if packet == ['\xff']:
            offset=0
        self.__read_options(packet[offset:])





    def create(self, option_type, )




    def __read_options(self, data):
        packet_data_list = []
        for char in data:
            packet_data_list.append(char)

        offset=0
        while True:
            option_type = ord(packet_data_list[offset])
            if option_type == self.END:
                break
            option_length = ord(packet_data_list[offset+1])
            data_start = offset + 2
            data_end = offset+2+option_length
            option_data = packet_data_list[data_start:data_end]

            option = DHCP_Packet_Option(option_type, ''.join(option_data))
            self.append(option)


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

            #options[self.OPTION_NAME[option_type]] = option_data
            offset += 2+option_length
        #return options



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




packet = '\x35\x01\x01\x01\x04\xff\xff\x00\x00\xff'
o = DHCP_Packet_Options(packet, 0)
print o
for oo in o:
    print oo.__dict__


empty_o = DHCP_Packet_Options()
print empty_o
