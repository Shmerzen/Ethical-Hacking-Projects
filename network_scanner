#!/usr/bin/env python3

import scapy as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether("ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for elements in answered_list:
        client_dict = {"ip": elements[1].psrc, "mac": elements[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def print_results(results):
    print("IP\t\t\tMAC\n--------------------------------------------------------------------------------------")
    for elements in results:
        print(elements["ip"] + "\t\t" + elements["mac"])


results = scan("10.0.2.1/24")
print_results(results)
