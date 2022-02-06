#!/usr/bin/env python3

import scapy.all as scapy
import argparse

def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--target", dest="target", help="target IP / IP range")
	options = parser.parse_args()
	return options

def scan(ip):
	# creating ARP request directed to boradcast MAC asking for IP 
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request # ARP request + broadcast MAC
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # to display only answered list
	
	# parse response
	clients_list = []
	for element in answered_list:
		client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
		clients_list.append(client_dict)
	return clients_list
	
def print_result(results_list):
	print("IP\t\t\tMAC Address")
	print("-------------------------------------")
	for client in results_list:
		print(client["ip"] + "\t\t" + client["mac"])

options = get_args()
scan_result = scan(options.target)
print_result(scan_result)
