#!/usr/bin/python3

import nmap3
import json

# pip install asciimatics , python3-nmap , google
# curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
# python3 get-pip.py

# nmap = nmap3.Nmap()
# print("Welcome ! This tool was made by Aous Mohammad")
# myTarget = input("Please enter your target to scan it :")
# results = nmap.scan_top_ports("nmmapper.com")
# results = nmap.nmap_dns_brute_script("nmmapper.com")
# result = json.loads(results)
# print(results)
# print("Do you want to see all ports ?")
# myChoose=input("please enter  (y/Y/yes) or (n/N/no) to complete :")
# if (myChoose == "y") or (myChoose == "yes") or (myChoose == "Y"):
#     print(result)    
# else:
# os_results = nmap.nmap_os_detection("192.168.178.2")
# version_result = nmap.nmap_version_detection("nmmapper.com")
# nmap = nmap3.NmapScanTechniques()
# result = nmap.nmap_fin_scan("192.168.178.1")
# result = nmap.nmap_idle_scan("192.168.178.1")
# result = nmap.nmap_ping_scan("192.168.178.1")
# result = nmap.nmap_syn_scan("192.168.178.1")
# result = nmap.nmap_tcp_scan("192.168.178.1")
# Only port scan (-Pn)
# Only host discover (-sn)
# Arp discovery on a local network (-PR)
# Disable DNS resolution (-n)
# def nmap_portscan_only(self, host, args=None)
# def nmap_no_portscan(self, host, args=None):
# def nmap_arp_discovery(self, host, args=None):
# def nmap_disable_dns(self, host, args=None):
# results = nmap3.scan_top_ports("host", args="-sV")
# $ nmap  -sL # (List Scan)
# $ nmap  -sn # (No port scan)
# $ nmap  -Pn # (No ping)
# $ nmap  -PS <port list> # (TCP SYN Ping)
# $ nmap -PA <port list> # (TCP ACK Ping)
# $ nmap  -PU <port list> # (UDP Ping)
# $ nmap  -PY <port list> # (SCTP INIT Ping)
# $ nmap  -PE; -PP; -PM # (ICMP Ping Types)
# $ nmap  -PO <protocol list> # (IP Protocol Ping)
# $ nmap  --disable-arp-ping # (No ARP or ND Ping)
# $ nmap  --traceroute # (Trace path to host)
# $ nmap  -n # (No DNS resolution)
# $ nmap  -R # (DNS resolution for all targets)
# $ nmap  --resolve-all # (Scan each resolved address)
# $ nmap  --system-dns # (Use system DNS resolver)
# $ nmap  --dns-servers <server1>[,<server2>[,...]] # (Servers to use for reverse DNS queries)
# git clone https://github.com/wangoloj/dnsdumpster.git
# git clone https://github.com/peterbrittain/asciimatics.git
# https://docs.python.org/3/library/curses.html