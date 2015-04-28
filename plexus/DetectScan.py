from pyshark import *

class DetectScan:
	def __init__(self):
		self.THRESHOLD_HOST_SCAN = 10
		self.THRESHOLD_PORT_SCAN = 1

	def host_scan(self, filename):
		cap_arp = FileCapture(filename)
		dict_arp = {}
		dict_attacker = {}
		for pkt in cap_arp:
			try:
				ipv4_src = pkt.ip.src
				ipv4_dst = pkt.ip.dst
				if ipv4_src in dict_arp.keys():
					dict_arp[ipv4_src].append(ipv4_dst)
					if len(dict_arp[ipv4_src]) > self.THRESHOLD_HOST_SCAN:
						if ipv4_src in dict_attacker.keys():
							if ipv4_dst not in dict_attacker[ipv4_src]:
								dict_attacker[ipv4_src].append(ipv4_dst)
						else:
							dict_attacker[ipv4_src] = dict_arp[ipv4_src]
				else:
					dict_arp[ipv4_src] = [ipv4_dst]
			except:
				pass

		for attacker in dict_attacker:
			print "Scanner IP: "+attacker
			print "#Hosts Scanned: "+str(len(list(set(dict_attacker[attacker]))))

	def port_scan(self, filename):
		cap_tcp = FileCapture(filename, display_filter='tcp.flags == 0x0002')
		dict_tcp = {}
		dict_attacker = {}
		for pkt in cap_tcp:
			ipv4_src = pkt.ip.src
			ipv4_dst = pkt.ip.dst
			if ipv4_src not in dict_tcp.keys():
				dict_tcp[ipv4_src] = {ipv4_dst:[pkt.tcp.dstport]}
			else:
				if ipv4_dst not in dict_tcp[ipv4_src].keys():
					dict_tcp[ipv4_src] = {ipv4_dst:[pkt.tcp.dstport]}
				else:
					dict_tcp[ipv4_src][ipv4_dst].append(pkt.tcp.dstport)
					if len(dict_tcp[ipv4_src][ipv4_dst]) > self.THRESHOLD_PORT_SCAN:
						if ipv4_src not in dict_attacker.keys():
							dict_attacker[ipv4_src] = [ipv4_dst]
						elif ipv4_src in dict_attacker.keys() and ipv4_dst not in dict_attacker[ipv4_src]:
							dict_attacker[ipv4_src].append(ipv4_dst)

		for attacker in dict_attacker.keys():
			print "Scanner IP: " + attacker
			print "Target IP's: " + str(dict_attacker[attacker])