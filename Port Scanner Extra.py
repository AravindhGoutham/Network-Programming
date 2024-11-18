#!/usr/bin/env python3

import argparse
import socket
from ipaddress import ip_network

def tcp_connect_scan(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                return "Open"
            else:
                return "Closed or Filtered"
    except socket.error:
        return "Closed or Filtered"

def udp_scan(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.sendto(b"", (ip, port))
            try:
                s.recvfrom(1024)
                return "Open"
            except socket.timeout:
                return "Open or Filtered"
    except socket.error:
        return "Closed"

def main():
    parser = argparse.ArgumentParser(description="Socket-based port scanner")
    parser.add_argument("ip", help="IP address or CIDR block to scan")
    parser.add_argument("-p", "--ports", nargs="+", type=int, help="Port(s) to scan", required=True)
    parser.add_argument("-t", "--type", choices=["tcp-syn", "udp"], required=True, help="Scan type")
    args = parser.parse_args()

    try:
        network = ip_network(args.ip, strict=False)
        ips = [str(ip) for ip in network]
    except ValueError:
        try:
            resolved_ip = socket.gethostbyname(args.ip)
            ips = [resolved_ip]
            print(f"Resolved {args.ip} to {resolved_ip}")
        except socket.gaierror:
            print(f"Could not resolve domain {args.ip}")
            return

    for ip in ips:
        print(f"Scanning {ip}...")
        for port in args.ports:
            if args.type == "tcp-syn":
                result = tcp_connect_scan(ip, port)
            elif args.type == "udp":
                result = udp_scan(ip, port)
            print(f"Port {port}: {result}")

if __name__ == "__main__":
    main()
