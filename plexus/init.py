import pyshark

def main():
	filename = 'tracefiles/port_scan'
	#nmap_host_scan(filename)
	nmap_port_scan(filename)

def nmap_host_scan(filename):
	cap_arp = pyshark.FileCapture(filename, display_filter='arp')
	dict_arp = {}
	for pkt in cap_arp:
		ipv4_src = pkt.arp.src_proto_ipv4
		ipv4_dst = pkt.arp.dst_proto_ipv4
		if ipv4_src in dict_arp.keys():
			dict_arp[ipv4_src].append(ipv4_dst)
		else:
			dict_arp[ipv4_src] = [ipv4_dst]

	for ipv4_src in dict_arp.keys():
		print ipv4_src+": "+str(len(dict_arp[ipv4_src]))

def nmap_port_scan(filename):
	cap_tcp = pyshark.FileCapture(filename, display_filter='tcp.flags == 0x0002')
	dict_tcp = {}
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

	#ports = sorted(list(set(dict_tcp['10.10.10.8']['104.237.151.15'])))
	#print ports
	#print len(ports)

def nmap_os_scan(filename):
	pass

if __name__ == "__main__":
	main()
