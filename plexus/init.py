import pyshark
import argparse
from Database import *
from DetectScan import *

def main():
	args = arguments()
	if args.file:
		#db = Database(args.file)
		pass
	if args.portscan:
		obj_scan = DetectScan()
		obj_scan.port_scan(args.file)
	if args.hostscan:
		obj_scan = DetectScan()
		obj_scan.host_scan(args.file)

def arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument('--file', '-f', required=True)
	parser.add_argument('--portscan', '-ps', action="store_true")
	parser.add_argument('--hostscan', '-hs', action="store_true")
	return parser.parse_args()


if __name__ == "__main__":
	main()
