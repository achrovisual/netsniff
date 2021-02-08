import sniffer
import signal
import socket, sys, os, re, time, netifaces
from scapy.all import *
import ipaddress
import collections

try:
    collectionsAbc = collections.abc
except AttributeError:
    collectionsAbc = collections

sniff = sniffer.Sniffer()

def arp_scan(ip):
    try:
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

        ans, unans = srp(request, timeout=2, retry=1, verbose = 0)
        result = []
        f = open("netsniff_dump.txt", "w")
        f.write("Connected Nodes:\n")
        for sent, received in ans:
            client = {'IP': received.psrc, 'MAC': received.hwsrc}
            f.write(str(client) + "\n")
            # print(client)
            result.append(client)
        f.close()
        return result
    except KeyboardInterrupt as e:
        sys.exit(0)

def main():
    # host_name = socket.gethostname()
    # host_ip = socket.gethostbyname(host_name)

    # ip = ipaddress.ip_interface(host_ip + '/0.0.0.0')
    # ip = ipaddress.ip_interface('172.16.0.0/255.240.0.0')
    # ip = input('Enter network address: ')
    # arp_scan(ip)

    sniff.initialize()
    # print(arp_scan(ip))

if __name__ == '__main__':
    try:
        t = Thread(target = main)
        t.daemon = True
        t.start()
        t.join()
    except KeyboardInterrupt as e:
        sniff.print_dump()
        sys.exit(0)
