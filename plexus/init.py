import pyshark
import argparse
from Database import *

def main():
	args = arguments()
	if args.file:
		db = Database(args.file)	

def arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument('--file', '-f', required=True)
	parser.add_argument('--portscan', '-ps', action="store_true")
	parser.add_argument('--hostscan', '-hs', action="store_true")
	return parser.parse_args()


if __name__ == "__main__":
	main()
