#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket, binascii, time, IN, thread
from json import dumps
from sys import exit



def packet_raw_output(string, hx=True):
	if hx:
		hx=0
	else:
		hx=1

	print '+-----------------'+ '-'*(4*hx) +'+'
	raw_data = []
	for char in string:
		raw_data.append( (hex(ord(char))[2:].rjust(2,'0'), str(ord(char)).rjust(3,'0')) )
		c = 0
	for id, dat in enumerate(raw_data):
		if c == 0:
			print '|'+ str(id).rjust(3,'0')+'|',
		print dat[hx],
		c += 1
		if c == 4:
			c=0
			print '|'
	print
	print '+-----------------'+ '-'*(4*hx) +'+'


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
	REQUESTED_IP			= 50
	IP_LEASE_TIME			= 51
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

class DHCP_Packet(object):
	RESPONSE	= 1
	REPLY 		= 2



	OPTION_TYPE = {
		0: 'PAD',
		1: 'SUBNET_MASK',
		3: 'ROUTER',
		6: 'DNS_SERVER',
		12: 'HOSTNAME',
		15: 'DOMAIN_NAME',
		26: 'MTU',
		28: 'BROADCAST',
		33: 'STATIC_ROUTING_TABLE',
		50: 'REQUESTED_IP',
		51: 'IP_LEASE_TIME',
		53: 'MSG_TYPE',
		54: 'SERVER_ID',
		55: 'PARAM_LIST',
		57: 'MAX_MSG_SIZE',
		58: 'RENEW_TIME_VALUE',
		59: 'REBINDING_TIME_VALUE',
		60: 'CLASS_ID',
		255:'END'
	}

	MSG_TYPE = {
		1: 'DHCPDiscover',
		2: 'DHCPOffer',
		3: 'DHCPRequest',
		4: 'DHCPDecline',
		5: 'DHCPAck',
		6: 'DHCPNak',
		7: 'DHCPRelease',
		8: 'DHCPInform'
	}


	def __init__(self, data):
		self.data = data
		self.op = ord(data[0])
		self.htype = ord(data[1])
		self.hlen = ord(data[2])
		self.hops = ord(data[3])
		self.xid = self.read_xid(data)
		self.secs = self.read_secs(data)
		self.flags = self.read_flags(data)
		self.client_ip = self.read_ip(data, 12)
		self.your_ip = self.read_ip(data, 16)
		self.server_ip = self.read_ip(data, 20)
		self.gateway_ip = self.read_ip(data, 24)
		self.client_hw_address = self.read_hw(data)
		self.client_hw_address_extention = self.read_hw_extention(data)
		self.additional_options_data = self.read_additional_options_data(data)
		self.magic_cookie = self.read_magic_cookie(data)



		for option in self.get_dhcp_options_raw(data):
			#print option
			if option[0] == Option_Type.HOSTNAME:
				self.dhcp_option_hostname = self.read_string(option)

			elif option[0] == Option_Type.MSG_TYPE:
				self.dhcp_message_type = option[1][0]

			elif option[0] == Option_Type.MAX_MSG_SIZE:
				self.dhcp_max_message_size = self.read_max_message_size(option)

			elif option[0] == Option_Type.CLASS_ID:
				self.dhcp_class_identifier = self.read_string(option)

			elif option[0] == Option_Type.PARAM_LIST:
				self.dhcp_parameter_list = option[1]

			elif option[0] == Option_Type.REQUESTED_IP:
				self.requested_ip = self.read_requested_ip(option)

			elif option[0] == Option_Type.SERVER_ID:
				self.requested_Server_ip = self.read_requested_ip(option)

			elif option[0] == Option_Type.END:
				pass

			elif option[0] == Option_Type.PAD: #####NOT IMPLENTED = read_pad()
				self.pad = 0


			else:
				print 'NOT KNOWN YET: ', option



		self.domain_name = 'local'



	def read_xid(self, data, offset=4):
		xid = [ord(data[offset]), ord(data[offset+1]), ord(data[offset+2]), ord(data[offset+3])]
		return xid

	def read_secs(self, data, offset=8):
		secs = [ord(data[offset]), ord(data[offset+1])]
		return secs

	def read_flags(self, data, offset=10):
		flags = [ord(data[offset]), ord(data[offset+1])]
		return flags

	def read_ip(self, data, offset=0):
		ip_data = (str(ord(data[offset])), str(ord(data[offset+1])), str(ord(data[offset+2])), str(ord(data[offset+3])))
		ip = '.'.join(ip_data)
		return ip

	def read_hw(self, data, offset=28):
		client_hw_data = (
		str(hex(ord(data[offset+0])))[2:].rjust(2,'0'),
		str(hex(ord(data[offset+1])))[2:].rjust(2,'0'),
		str(hex(ord(data[offset+2])))[2:].rjust(2,'0'),
		str(hex(ord(data[offset+3])))[2:].rjust(2,'0'),
		str(hex(ord(data[offset+4])))[2:].rjust(2,'0'),
		str(hex(ord(data[offset+5])))[2:].rjust(2,'0'))
		client_hw = ':'.join(client_hw_data)

		#print client_hw, client_hw_data
		return client_hw

	def read_hw_extention(self, data, offset=28):
		return data[offset+6:offset+16]

	def read_additional_options_data(self, data, offset=43):
		return data[offset:offset+192]

	def read_magic_cookie(self, data, offset=236):
		magic_cookie = [ord(data[offset]), ord(data[offset+1]), ord(data[offset+2]), ord(data[offset+3])]
		return magic_cookie



	def get_dhcp_options_raw(self, data):
		dhcp_options = []
		next_offset = 0
		try:
			while True:
		 		option_type, option_content, next_offset = self.get_dhcp_option(data, next_offset)
				dhcp_options.append((option_type, option_content))
		except IndexError:
			pass
		return dhcp_options

	def get_dhcp_option(self, data, offset=0):
		address = offset + 240
		dhcp_option_type = ord(data[address])
		address += 1
		dhcp_option_length = ord(data[address])
		address += 1
		dhcp_option_content = []

		for char in data[address:address + dhcp_option_length]:
			dhcp_option_content.append(ord(char))

		address += dhcp_option_length
		next_offset = address - 240
		return (dhcp_option_type, dhcp_option_content, next_offset)


	def read_string(self, option):
		string = ''
		for byte in option[1]:
			string += chr(byte)
		return string

	def read_max_message_size(self, option):
		value_1 = option[1][0]
		value_256 = option[1][1]
		return (value_256 * 256) + value_1

	def read_requested_ip(self, option):
		ip = []
		for byte in option[1]:
			ip.append(str(byte))
		return '.'.join(ip)


	def is_dhcp_discovery(self):
		if self.dhcp_message_type == Message_Type.DHCPDiscover:
			return True
		return False

	def is_dhcp_request(self):
		if self.dhcp_message_type == Message_Type.DHCPRequest:
			return True
		return False



	def generate_dhcp_paket(self, message_type, your_ip, server_ip):
		self.op = self.REPLY
		self.your_ip = your_ip
		self.server_ip = server_ip
		self.dhcp_message_type = message_type

		lease_time = 60
		lease_time_bytes = binascii.unhexlify(hex(lease_time)[2:].rjust(8,'0'))
		lease_time_option_list = []
		for char in lease_time_bytes:
			lease_time_option_list.append(ord(char))
		lease_time_option = (51,lease_time_option_list)

		tftp_address = server_ip
		tftp_address_option_list = []
		for char in tftp_address:
			tftp_address_option_list.append(ord(char))
		tftp_address_option = (66,tftp_address_option_list)

		tftp_file = 'pxelinux.0'
		tftp_file_option_list = []
		for char in tftp_file:
			tftp_file_option_list.append(ord(char))
		tftp_file_option = (67,tftp_file_option_list)

		domain_name = self.domain_name
		domain_name_option_list = []
		for char in domain_name:
			domain_name_option_list.append(ord(char))
		domain_name_option = (15,domain_name_option_list)



		host_name = self.dhcp_option_hostname
		host_name_option_list = []
		for char in host_name:
			host_name_option_list.append(ord(char))
		host_name_option = (12,host_name_option_list)


		options = [
			(53,[self.dhcp_message_type]),
			(1,[255,255,0,0]),
			(54,[10,10,10,2]),
			(28,[10,10,255,255]),
			(3,[10,10,0,1]),
			(6,[8,8,8,8,8,8,4,4]),
			domain_name_option,
			host_name_option,
			lease_time_option,
			tftp_address_option,
			tftp_file_option
		]

		options_string = self.generate_dhcp_options(options)
		packet_string = self.generate_packet(options_string)
		return packet_string


	def generate_dhcp_options(self, options):
		options_string = ''
		for option in options:
			options_string += self.generate_dhcp_option(option)
		return options_string

	def generate_dhcp_option(self, option):
		option_type = option[0]
		option_length = len(option[1])
		option_payload = option[1]
		option_packet = [option_type, option_length]
		option_packet.extend(option_payload)
		return self.generate_string(option_packet)

	def generate_string(self, byte_list):
		string = ''
		for byte in byte_list:
			string += chr(byte)
		return string

	def generate_packet(self, options_string):
		packet_string = ''
		packet_string += chr(self.op)
		packet_string += chr(self.htype)
		packet_string += chr(self.hlen)
		packet_string += chr(self.hops)
		packet_string += self.generate_string(self.xid)
		packet_string += self.generate_string(self.secs)
		packet_string += self.generate_string(self.flags)
		packet_string += self.generate_string(self.write_ip(self.client_ip))
		packet_string += self.generate_string(self.write_ip(self.your_ip))
		packet_string += self.generate_string(self.write_ip(self.server_ip))
		packet_string += self.generate_string(self.write_ip(self.gateway_ip))

		packet_string += self.generate_string(self.write_hw(self.client_hw_address))
		packet_string += self.client_hw_address_extention
		packet_string += self.additional_options_data
		packet_string += self.generate_string(self.magic_cookie)
		packet_string += options_string
		packet_string += chr(0)+chr(255)
		return packet_string

	def write_ip(self, ip_string):
		ip_string = ip_string.split('.')
		ip = []
		for byte in ip_string:
			try:
				ip.append(int(byte))
			except:
				break
		return ip

	def write_hw(self, hw_string):
		hw_string = hw_string.split(':')
		hw = []
		for byte in hw_string:
			byte = int(byte, 16)
			try:
				hw.append(int(byte))
			except:
				break
		return hw

class DHCPRangeError(Exception):
	pass

class Lease(dict):
	def __init__(self, **keyword_args):
		dict.__init__(self, keyword_args)
		self.in_use()

		if not 'hostname' in self.keys():
			self['hostname'] = None
			self.hostname = self['hostname']

		if not 'mac' in self.keys():
			self['mac'] = '00:00:00:00:00:00'
			self.mac = self['mac']
			self.in_use(False)

		if not 'ip' in self.keys():
			self['ip'] = '0.0.0.0'
			self.ip = self['ip']
			self.in_use(False)

		if not 'time' in self.keys():
			self['time'] = 86400
		self.time = self['time']


		self.update_create_time()


	def update_create_time(self):
		self['create_time'] = int(time.time())
		self.create_time = self['create_time']
		self['lease_ends'] = self.create_time + self.time
		self.lease_ends = self['lease_ends']

	def update_ip(self, ip):
		self['ip'] = ip
		self.ip = self['ip']
		self.in_use()
		self.update_create_time()

	def in_use(self, value=True):
		self['active'] = value
		self.active = value

	def __str__(self):
		return dumps(self, indent=4)

class Leases(dict):
	def __init__(self, ip_range, **keyword_args):
		dict.__init__(self, keyword_args)
		self.__range = ip_range
		self.range_int = self.__calculate_range()
		self.max_range_int_id = len(self.range_int) - 1
		self.current_range_int_id = 0
		self.used_ip_list = []


	def __calculate_range(self):
		range_from = self.__calculate_ip_string_to_int(self.__range[0])
		range_to = self.__calculate_ip_string_to_int(self.__range[1])
		if range_from >= range_to:
			raise DHCPRangeError()

		return self.__generate_ip_range_int(range_from, range_to)

	def __calculate_ip_string_to_int(self, ip_string):
		ip_list = ip_string.split('.')
		ip_list = [ int(ip_list[0]), int(ip_list[1]), int(ip_list[2]), int(ip_list[3]) ]
		ip = 0
		ip += ip_list[0] * 16777216
		ip += ip_list[1] * 65536
		ip += ip_list[2] * 256
		ip += ip_list[3]
		return ip

	def __calculate_ip_int_to_string(self, ip):
		ip_hex = hex(ip)
		ip_hex = ip_hex[2:].rjust(8,'0')
		ip_0 = int(ip_hex[:2].rjust(2,'0'), 16)
		ip_1 = int(ip_hex[2:4].rjust(2,'0'), 16)
		ip_2 = int(ip_hex[4:6].rjust(2,'0'), 16)
		ip_3 = int(ip_hex[6:8].rjust(2,'0'), 16)
		ip_list = [str(ip_0), str(ip_1), str(ip_2), str(ip_3)]
		ip_string = '.'.join(ip_list)
		return ip_string

	def __generate_ip_range_int(self, from_ip, to_ip):
		ip_range_int_list = []
		for ip_int in xrange(from_ip, to_ip + 1):
			ip_range_int_list.append(ip_int)
		return ip_range_int_list

	def create(self, mac, ip=False, **keyword_arg):
		if not 'hostname' in keyword_arg.keys():
			hostname = None
		else:
			hostname = keyword_arg['hostname']

		if not 'time' in keyword_arg.keys():
			lease_time = 3600
		else:
			lease_time = keyword_arg['time']

		if not self.__exists_lease(mac):
			if ip == False:
				ip = self.__get_ip()
			if ip == False:
				return False

			if not self.__is_ip_in_range(ip):
				return False

			if not self.__is_ip_in_use(ip):
				self[mac] = Lease(mac=mac, ip=ip, hostname=hostname, time=lease_time)
				self.used_ip_list.append(ip)
				return self[mac]
		else:
			return self.get_ip(mac)

		return False

	def __exists_lease(self, mac):
		return mac in self.keys()

	def exists_lease(self, mac):
		if mac in self.keys():
			return self[mac]
		return False

	def __is_ip_in_use(self, ip):
		return ip in self.used_ip_list

	def __is_ip_in_range(self, ip):
		ip = self.__calculate_ip_string_to_int(ip)
		if ip >= self.range_int[0] and ip <= self.range_int[-1]:
			return True
		return False

	def update_ip(self, mac, ip):
		self[mac].update_ip(ip)

	def __get_ip(self):
		for ip in self.range_int:
			ip = self.__calculate_ip_int_to_string(ip)
			if not self.__is_ip_in_use(ip):
				return ip
		return False

	def get_ip(self, mac):
		try:
			return self[mac]['ip']
		except KeyError:
			return False

	def resolv_ip(self, ip):
		for lease_key in self.keys():
			if self[lease_key]['ip'] == ip:
				return lease_key

	def delete(self, ip):
		try:
			ip_index = self.used_ip_list.index(ip)
		except ValueError:
			return False
		mac = self.resolv_ip(ip)
		del self[mac]
		del self.used_ip_list[ip_index]
		return True

class DHCP_Server(object):
	def __init__(self, interface, server_ip, netmask):
		self.interface = interface
		self.mtu = self.__get_mtu()
		self.port = 67
		self.server_ip = server_ip
		self.netmask = netmask
		self.gateway = server_ip
		self.dns = ['8.8.8.8', '8.8.4.4']
		self.range = ['10.10.50.1','10.10.50.9']
		self.default_lease_time = 60
		self.leases = Leases(self.range)
		self.discoveries = []
		self.check_thread = thread.start_new_thread(self.delete_expired_leases ,(True,))


		print self.interface, self.mtu




	def delete_expired_leases(self, v):
		while True:
			for mac in self.leases.keys():
				current_time = int(time.time())
				print self.leases.used_ip_list
				if current_time >= self.leases[mac]['lease_ends'] - 2:
					ip_id = self.leases.used_ip_list.index(self.leases[mac]['ip'])
					del self.leases.used_ip_list[ip_id]
					del self.leases[mac]
					print mac, 'deleted.'
					break

			time.sleep(1)


	def __get_mtu(self):
		with open('/sys/class/net/'+self.interface+'/mtu') as mtu:
			mtu = mtu.read()
		return int(mtu)

	def run(self):
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

				if packet.is_dhcp_discovery(): #############################DHCPDiscover
					lease = self.leases.exists_lease(mac_address)
					if lease == False:
						lease = self.leases.create(mac_address, time=self.default_lease_time)
						if lease == False:
							self.send_Nak(s, packet)
					else:
						self.send_Offer(s, packet, lease['ip'])
				elif packet.is_dhcp_request():
					lease = self.leases.exists_lease(mac_address)
					if lease == False:
						self.send_Nak(s, packet)
					else:
						self.send_Ack(s, packet, lease['ip'])
						print 'LEASED:', lease['ip']


			except KeyboardInterrupt:
				exit()



	def send_Nak(self, s, packet):
		data = packet.generate_dhcp_paket(Message_Type.DHCPNak, '0.0.0.0', self.server_ip)
		if data:
			s.sendto(data,('<broadcast>',68)) ##################DHCPNack
			return True
		return False

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



#dhcp = DHCP_Server('wlan0','10.10.10.2','255.255.0.0')
#dhcp.run()





#exit()
