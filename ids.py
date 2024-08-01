import re
import argparse
import os
import subprocess
import random
import threading
import time
import binascii
from scapy.all import *

black_list = []
white_list = []
channel_list = list(range(1,15))
freq_dict = {}

monitor_timer = 5
outfile = None
alertfile = None
alert_tracker = {}
threshold = 10
window_size = 50

def parseframe(frame):
	if frame.haslayer(Dot11):
		#NUL frames (sent to victim)
		if frame.getlayer(Dot11).type == 0x2 and frame.getlayer(Dot11).subtype == 0x4:
			target = frame.getlayer(Dot11).addr1
			tstamp = frame.getlayer(RadioTap).timestamp
			if black_list and target in black_list:
				return
			if white_list and not target in white_list:
				return
			print('NUL', frame.getlayer(Dot11).addr2, 
					target,
					frame.getlayer(RadioTap).dBm_AntSignal,
					frame.getlayer(RadioTap).ChannelFlags,
					frame.getlayer(RadioTap).ChannelFrequency,
					tstamp)
			if outfile:
				with open(outfile, 'a') as f:
					f.write(' '.join(
							[str(x) for x in
							[freq_dict[frame.getlayer(RadioTap).ChannelFrequency],
							target,
							frame.getlayer(Dot11).addr2]])
							+ ' '
							+ binascii.hexlify(frame.original).decode()
							+ '\n')
			if not target in alert_tracker:
				alert_tracker[target] = []
			alert_tracker[target].append(tstamp)

			timespan = (alert_tracker[target][-1] - alert_tracker[target][0])/1000000

			if (len(alert_tracker[target]) >= window_size) and (timespan < threshold):
				astr = 'Possible attack against {}; {} nul frames in {}'.format(target, 
													len(alert_tracker[target]), timespan)
				print(astr)
				with open(alertfile, 'a') as f:
					f.write(astr+'\n')
				alert_tracker[target].clear()

			if len(alert_tracker[target]) > window_size:
				del alert_tracker[target][0:-11]

def channelhop():
	print(channel_list)
	while (True):
		random.shuffle(channel_list)
		for i in channel_list:
			print('MONITORING CHANNEL {}'.format(i))
			os.system('iwconfig {} channel {}'.format(interface, i))
			#print('iwconfig wlan0mon channel {}'.format(i))
			time.sleep(monitor_timer)

#sudo airmon-ng check kill
#sudo airmon-ng start wlan0

def get_freqs():
	a = subprocess.check_output(['iwlist', interface, 'channel'])
	chans = re.findall(b'Channel (\\d+) : (\d\.\d+) GHz', a)
	r = [[int(float(x[1])*1000), int(x[0])] for x in chans]
	for c in r:
		freq_dict[c[0]] = c[1]


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-c', '--channels', nargs='+', default=channel_list, help='Channels to monitor')
	parser.add_argument('-i', '--interface', default='wlan0mon', help='Interface to monitor')
	parser.add_argument('-b', '--blacklist', nargs='+', default=[], help='Blacklist of mac addresses to avoid targeting')
	parser.add_argument('-w', '--whitelist', nargs='+', default=[], help='Whitelist of mac addresses to target')
	parser.add_argument('-t', '--time', default=monitor_timer, type=int, help='Time to monitor a channel before switching')
	parser.add_argument('-l', '--logfile', default=None, help='Log file for recording observed NUL traffic, regardless of attack status')
	parser.add_argument('-a', '--alerts', default='./alerts.txt', help='Output file for saving alerts')

	args = parser.parse_args()
	
	channel_list = args.channels
	interface = args.interface
	black_list = [x.lower() for x in args.blacklist]
	white_list = [x.lower() for x in args.whitelist]
	monitor_timer = args.time
	outfile = args.logfile
	alertfile = args.alerts

	get_freqs()

	thread = threading.Thread(target=channelhop, name="Hop")
	thread.daemon = True
	thread.start()

	sniff(iface=interface, prn=parseframe, store=0)