

class DHCP_Server(object):
	def __init__(self, interface, server_ip, netmask):
		self.interface = interface
		self.mtu = self.__get_mtu()
		self.port = 67
		self.server_ip = server_ip
		self.netmask = netmask
		self.gateway = server_ip
		self.dns = ['8.8.8.8', '8.8.4.4']
		self.ntp = 'de.pool.ntp.org'
		self.range = ['10.10.50.1','10.10.50.9']
		self.default_lease_time = 60
		self.leases = Leases(self.server_ip, self.netmask, ip_range=self.range)

        self.dhcp_thread = thread.start_new_thread(self.run,(None,))




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
                    print packet

				# 	lease = self.leases.exists_lease(mac_address)
				# 	if lease == False:
				# 		lease = self.leases.create(mac_address, time=self.default_lease_time)
				# 		if lease == False:
				# 			self.send_Nak(s, packet)
				# 	else:
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
