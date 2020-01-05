#!/usr/bin/env python

import scapy.all as scapy
import optparse           #argparse the new version of optparse

def scan(ip):
  arp_request = scapy.ARP(pdst=ip)
  broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
  arp_request_broadcast = broadcast/arp_request
  answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

  clients_list = []

  for element in answered_list:
      client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}    #dictionary in python
      clients_list.append(client_dict)                                  # add the dict to the big list

  return clients_list


def print_result(result_list):

  print("------------------------------------------")
  print("  IP\t\t\t   MAC address ")
  print("------------------------------------------")
  for client in result_list:
    print(client["ip"] + "\t\t" + client["mac"])


def get_network():
  parser = optparse.OptionParser()

  parser.add_option("-t", "--target", dest="target", help="Target IP/ IP range. ")
  (options, arguments) = parser.parse_args()

  if not options.target:
    parser.error(" [-] Please specify an ip or a network range, use --help for more info.")
  return options


options = get_network()
scan_result = scan(options.target)
print_result(scan_result)



#scapy.ls(scapy.ARP())                    #list all the field in the scapy.arp
