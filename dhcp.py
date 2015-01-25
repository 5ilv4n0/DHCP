#!/usr/bin/env python

#dhcpd.py pure python dhcp server pxe capable
#psychomario - https://github.com/psychomario

import socket, binascii, time, IN

from sys import exit
from optparse import OptionParser
import json




class Packet(object):

	class Option_Type:
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


	OPTION_TYPE = {
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
		60: 'CLASS_ID'
	}


	def __init__(self, data):
		self.data = data
		#for char in data:
		#	self.data.append( hex(ord(char))[2:].rjust(2,'0')+'[' + str(ord(char)).rjust(3,'0') + ']' )

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
			if option[0] == self.Option_Type.HOSTNAME:
				self.dhcp_option_hostname = self.read_string(option)

			elif option[0] == self.Option_Type.MSG_TYPE:
				self.dhcp_message_type = option[1][0]

			elif option[0] == self.Option_Type.MAX_MSG_SIZE:
				self.dhcp_max_message_size = self.read_max_message_size(option)

			elif option[0] == self.Option_Type.CLASS_ID:
				self.dhcp_class_identifier = self.read_string(option)

			elif option[0] == self.Option_Type.PARAM_LIST:
				self.dhcp_parameter_list = option[1]
				for param in self.dhcp_parameter_list:
					print self.OPTION_TYPE[param]

			elif option[0] == self.Option_Type.REQUESTED_IP:
				self.requested_ip = self.read_requested_ip(option)

			else:
				print 'NOT KNOWN YET: ', option





		# print 'MSG_TYPE:    ', self.MSG_TYPE[self.dhcp_message_type]
		# print 'HOSTNAME:    ', repr(self.dhcp_option_hostname)
		# print 'MAXMSGSIZE:  ', self.dhcp_max_message_size
		# print 'CLASS_IDENT: ', self.dhcp_class_identifier
		# print 'PARAM_LIST:  ', self.dhcp_parameter_list
		# print



		# self.raw_data = []
		# for char in self.data:
		# 	self.raw_data.append( hex(ord(char))[2:].rjust(2,'0')+'[' + str(ord(char)).rjust(3,'0') + ']' )
		# c = 0
		# for id, d in enumerate(self.raw_data):
		# 	if c == 0:
		# 		print str(id).rjust(3,'0')+': ',
		# 	print d,
		# 	c += 1
		# 	if c == 4:
		# 		c=0
		# 		print





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
		if self.dhcp_message_type == 1:
			return True
		return False

	def is_dhcp_request(self):
		if self.dhcp_message_type == 3:
			return True
		return False



	def generate_dhcp_offer_paket(self, your_ip, server_ip):
		self.op = 2
		self.your_ip = your_ip
		self.server_ip = server_ip
		self.dhcp_message_type = 2

		lease_time = 3600
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

		options = [
			(53,[self.dhcp_message_type]),
			(1,[255,255,0,0]),
			(54,[10,10,10,2]),
			(28,[10,10,255,255]),
			(3,[10,10,0,1]),
			(6,[8,8,8,8,8,8,4,4]),
			lease_time_option,
			tftp_address_option,
			tftp_file_option
		]

		options_string = self.generate_dhcp_options(options)
		packet_string = self.generate_packet(options_string)
		return packet_string

	def generate_dhcp_ack_paket(self, your_ip, server_ip):
		self.op = 2
		self.your_ip = your_ip
		self.server_ip = server_ip
		self.dhcp_message_type = 5

		lease_time = 3600
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

		options = [
			(53,[self.dhcp_message_type]),
			(1,[255,255,0,0]),
			(54,[10,10,10,2]),
			(28,[10,10,255,255]),
			(3,[10,10,0,1]),
			(6,[8,8,8,8,8,8,4,4]),
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
















if not hasattr(IN, 'SO_BINDTODEVICE'):
	IN.SO_BINDTODEVICE = 25  #http://stackoverflow.com/a/8437870/541038

def release(): #release a lease after timelimit has expired
    for lease in leases:
       if not lease[1]:
          if time.time()+leasetime == leasetime:
              continue
          if lease[-1] > time.time()+leasetime:
             print "Released",lease[0]
             lease[1]=False
             lease[2]='000000000000'
             lease[3]=0




interface = 'wlan0'
port = 67
server_ip = '10.10.10.2'
netmask = '255.255.0.0'
gateway = '10.10.0.1'
dns = '8.8.8.8'
range_from = '10.10.50.1'
range_to = '10.10.50.254'
lease_time = 3600



s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,IN.SO_BINDTODEVICE, interface+'\0') #experimental
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(('',port))


while True:
	try:
		message, addressf = s.recvfrom(8192)
        #if not message.startswith('\x01') and not addressf[0] == '0.0.0.0':
            #continue #only serve if a dhcp request
		print '---------------------------'

		packet = Packet(message)
		if packet.is_dhcp_discovery():
			data = packet.generate_dhcp_offer_paket(range_from,server_ip)
			if data:
				s.sendto(data,('<broadcast>',68))

		elif packet.is_dhcp_request():
			data = packet.generate_dhcp_ack_paket(range_from,server_ip)
			if data:
				s.sendto(data,('<broadcast>',68))
			print 'LEASED:', range_from


        #release() #update releases table
	except KeyboardInterrupt:
		exit()
#    except:
#        continue
