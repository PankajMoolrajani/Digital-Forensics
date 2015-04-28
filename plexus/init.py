import pyshark

def main():
	filename = 'tracefiles/port_scan'
	#nmap_host_scan(filename)
	nmap_port_scan(filename)


if __name__ == "__main__":
	main()
