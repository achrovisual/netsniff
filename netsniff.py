from datetime import datetime
import ipcalc
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

now = datetime.now()
dt_string = now.strftime("%Y-%m-%d %H.%M.%S")
filename = "netsniff_dump " + dt_string + ".txt"

def arp_scan(ip):
    try:
        print("[*] Scanning " + ip + "...")
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

        ans, unans = srp(request, timeout=2, iface='ens18', inter=0.1, verbose = 0)
        result = []
        f = open(filename, "w")
        f.write("****IP:MAC Mapping****\n")
        for sent, received in ans:
            client = {'IP': received.psrc, 'MAC': received.hwsrc}
            f.write(str(client) + "\n")
            # print(client)
            result.append(client)

        if result == []:
            f.write("None found.\n")

        f.write("\n")
        f.close()
        return result
    except KeyboardInterrupt as e:
        sys.exit(0)

def main():
    ip = netifaces.ifaddresses('ens18')[netifaces.AF_INET][0]['addr']
    subnet = netifaces.ifaddresses('ens18')[netifaces.AF_INET][0]['netmask']

    addr = ipcalc.IP(ip, mask=subnet)

    arp_scan(str(addr.guess_network()))

    sniff.initialize()

if __name__ == '__main__':
    try:
        t = Thread(target = main)
        t.daemon = True
        t.start()
        t.join()
    except KeyboardInterrupt as e:
        try:
            sniff.print_dump(filename)
        except:
            sys.exit(0)
