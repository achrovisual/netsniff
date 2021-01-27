import signal
import socket, sys, os, re, time, netifaces
from scapy.all import *
import ipaddress
import collections

try:
    collectionsAbc = collections.abc
except AttributeError:
    collectionsAbc = collections

def arp_scan(ip):
    try:
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

        ans, unans = srp(request, timeout=2, retry=1)
        result = []
        f = open("MAC-IP Mapping.txt", "w")
        f.write("Connected Nodes:\n")
        for sent, received in ans:
            client = {'IP': received.psrc, 'MAC': received.hwsrc}
            f.write(str(client) + "\n")
            print(client)
            result.append(client)
        f.close()
        return result
    except KeyboardInterrupt as e:
        sys.exit(0)


try:
    # host_name = socket.gethostname()
    # host_ip = socket.gethostbyname(host_name)

    # ip = ipaddress.ip_interface(host_ip + '/0.0.0.0')
    # ip = ipaddress.ip_interface('172.16.0.0/255.240.0.0')
    ip = input('Enter network address: ')
    print(arp_scan(ip))
except KeyboardInterrupt as e:
    sys.exit(0)
