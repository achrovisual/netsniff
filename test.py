import signal
import socket, sys, os, re, time, netifaces
from scapy.all import *
import ipaddress
import collections
from threading import Thread, Event
from time import sleep

dhcpCount, httpCount, httpsCount, arpCount, ftpCount, sshCount = 0, 0, 0, 0, 0, 0



class Sniffer(Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True

        self.socket = None
        self.stopper = Event()

    def run(self):
        self.socket = conf.L2listen(type=ETH_P_ALL, filter="ip")

        sniff(opened_socket=self.socket, prn=self.checkHandler, stop_filter=self.filterStopper)

    def checkHandler(self, packet):
        global dhcpCount, httpCount, httpsCount, arpCount, ftpCount, sshCount
        if IP in packet:
            srcIP = packet[IP].src
            dstIP = packet[IP].dst

        if ARP in packet and (packet[ARP].op == 1 or packet[ARP].op == 2):
            arpCount+=1
        elif IP in packet and (packet[IP].sport == 67 or packet[IP].dport == 68):
            dhcpCount+=1
        elif IP in packet and (packet[IP].dport == 20 or packet[IP].dport == 21 or packet[IP].sport == 20 or packet[IP].sport == 21):
            ftpCount+=1
        elif IP in packet and (packet[IP].dport == 80 or packet[IP].sport == 80):
            httpCount+=1
        elif IP in packet and (packet[IP].dport == 443 or packet[IP].sport == 443):
            httpsCount+=1
        elif IP in packet and (packet[IP].dport == 22 or packet[IP].sport == 22):
            sshCount+=1

        print("[!] New Packet: {src} : {sport} -> {dst} : {dport}".format(src=srcIP, dst=dstIP, sport = packet[IP].sport, dport = packet[IP].dport))
    def filterStopper(self, packet):
        return self.stopper.isSet()

    def join(self, timeout=None):
        self.stopper.set()
        super().join(timeout)

sniffer = Sniffer()

print("[*] Sniffer initialized...")
print("***Tip: Use CTRL + C to end sniffing.***")
sniffer.start()

try:
    while True:
        sleep(100)

except KeyboardInterrupt as e:
    sniffer.join()
    print("\n\n\n[*] Sniffing stopped.\n")
    print("****Protocol Statistics:****\n")
    print("ARP Count: " + str(arpCount))
    print("DHCP Count: " + str(dhcpCount))
    print("FTP Count: " + str(ftpCount))
    print("HTTP Count: " + str(httpCount))
    print("HTTPS Count: " + str(httpsCount))
    print("SSH Count: " + str(sshCount))
    

    if sniffer.is_alive():
        sniffer.socket.close()
        sys.exit()
