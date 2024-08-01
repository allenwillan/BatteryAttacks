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

monitor_timer = 5
outfile = None

done_target = set([])
success_target = set([])
failed_target = set([])
pending_target = set([])
bad_target = set(['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', None])
fake_addr = 'de:ad:de:ad:90:00'

def targetinggparseframe(frame):
	if frame.haslayer(Dot11):
		f = frame.getlayer(Dot11)
		if not f.addr1 in done_target and f.addr1 not in bad_target:
			pending_target.add(f.addr1)
		if not f.addr2 in done_target and f.addr2 not in bad_target:
			pending_target.add(f.addr2)
		if not f.addr3 in done_target and f.addr3 not in bad_target:
			pending_target.add(f.addr3)

def attack_withtest():
	while (True):
		random.shuffle(channel_list)
		for c in channel_list:
			print('MONITORING CHANNEL {}'.format(c))
			os.system('iwconfig {} channel {}'.format(interface, c))

			#listen for targets
			print(' Listening for {}s'.format(monitor_timer))
			sniff(prn=targetinggparseframe, store=0, timeout=monitor_timer, iface=interface)

			for target in pending_target:
				if not target: continue
				if black_list and (target in black_list):
					bad_target.add(target)
					continue
				if white_list and not (target in white_list):
					bad_target.add(target)
					continue
				print(' Probing {}'.format(target))
				fake_station = fake_addr
				if not fake_addr:
					#fake_station = 'fa:ce:fa:ce:'
					#back = hex(random.randint(0x1000,0xFFFF)).split('x')[1]
					#fake_station += back[:2] + ':' + back[2:]
					fake_station = random.randbytes(6)
					fake_station = ':'.join(['{:02x}'.format(x) for x in fake_station])
				p = AsyncSniffer(iface=interface)
				p.start()
				t = RadioTap()/Dot11(addr1=target, addr2=fake_station, addr3=target, type=0x2, subtype=0x4,
											FCfield=0x01, ID=0x6602, SC=0x9090)
				for i in range(0, 5):
					sendp(t, iface=interface, verbose=False)
				time.sleep(1)
				p.stop()

				found = False
				for frame in p.results:
					if frame.haslayer(Dot11):
						#ACK frame (response from victim)
						if frame.getlayer(Dot11).type == 0x1 and frame.getlayer(Dot11).subtype == 0xd:
							if frame.getlayer(Dot11).addr1 == fake_station:
								success_target.add(target)
								print('  TARGET FOUND: {}'.format(target))
								found = True
								with open(outfile, 'a') as f:
									f.write(' '.join([str(x) for x in [c, target, 'SUCC']])+ '\n')
								break
				if not found:
					failed_target.add(target)
					with open(outfile, 'a') as f:
						f.write(' '.join([str(x) for x in [c, target, 'FAIL']])+ '\n')
				done_target.add(target)
				time.sleep(1)
			pending_target.clear()

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-c', '--channels', nargs='+', default=channel_list, help='Channels to monitor')
	parser.add_argument('-i', '--interface', default='wlan0mon', help='Interface to monitor')
	parser.add_argument('-b', '--blacklist', nargs='+', default=[], help='Blacklist of mac addresses to avoid targeting')
	parser.add_argument('-w', '--whitelist', nargs='+', default=[], help='Whitelist of mac addresses to target')
	parser.add_argument('-t', '--time', default=monitor_timer, type=int, help='Time to monitor a channel before switching')
	parser.add_argument('-o', '--outfile', default='./probes.out', help='Output file for recording')
	parser.add_argument('-f', '--fake', default=None, help='Fake MAC address to use (default is random bytes)')

	args = parser.parse_args()
	
	channel_list = args.channels
	interface = args.interface
	black_list = [x.lower() for x in args.blacklist]
	white_list = [x.lower() for x in args.whitelist]
	monitor_timer = args.time
	outfile = args.outfile
	fake_addr = args.fake

	attack_withtest()