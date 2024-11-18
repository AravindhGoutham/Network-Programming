#!/usr/bin/env python3

import argparse
from scapy.all import *

def tcp_syn_scan(ip, port):
    syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
    response = sr1(syn_packet, timeout=1, verbose=0)
    if response:
        if response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN-ACK
            send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=0)  # Reset connection
            return "Open"
        elif response.haslayer(TCP) and response[TCP].flags == 0x14:  # RST
            return "Closed"
    return "Filtered or No Response"

def tcp_ack_scan(ip, port):
    ack_packet = IP(dst=ip) / TCP(dport=port, flags="A")
    response = sr1(ack_packet, timeout=1, verbose=0)
    return "Unfiltered" if response else "Filtered"

def udp_scan(ip, port):
    udp_packet = IP(dst=ip) / UDP(dport=port)
    response = sr1(udp_packet, timeout=1, verbose=0)
    return "Open or Filtered" if not response else "Closed"

def main():
    parser = argparse.ArgumentParser(description="Simple Scapy-based port scanner")
    parser.add_argument("ip", help="IP address or CIDR block to scan")
    parser.add_argument("-p", "--ports", nargs="+", type=int, help="Port(s) to scan", required=True)
    parser.add_argument("-t", "--type", choices=["tcp-syn", "tcp-ack", "udp"], required=True, help="Scan type")
    args = parser.parse_args()

    for port in args.ports:
        if args.type == "tcp-syn":
            result = tcp_syn_scan(args.ip, port)
        elif args.type == "tcp-ack":
            result = tcp_ack_scan(args.ip, port)
        elif args.type == "udp":
            result = udp_scan(args.ip, port)
        print(f"Port {port}: {result}")

if __name__ == "__main__":
    main()
