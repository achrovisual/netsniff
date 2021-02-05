import signal
import socket, sys, os, re, time, netifaces
from scapy.all import *
import ipaddress
import collections
from threading import Thread
from time import sleep

dhcpCount = 0
httpCount = 0
httpsCount = 0
arpCount = 0
ftpCount = 0


class Sniffer(Thread):
    def __init__(self):
        super().__init__()
    
    def run(self):
        sniff(filter = "ip", prn = self.checkHandler)

    def checkHandler(self, packet):
        global dhcpCount, httpCount, httpsCount, arpCount, ftpCount

        if ARP in packet and (packet[ARP].op == 1 or packet[ARP].op == 2):
            arpCount+=1
        elif IP in packet and (packet[IP].sport == 67 or packet[IP].dport == 68):
            dhcpCount+=1
        elif IP in packet and (packet[IP].dport == 20 or packet[IP].dport == 21 or packet[IP].sport == 20 or packet[IP].sport == 21):
            ftpCount+=1
        elif IP in packet and (packet[IP].dport == 80 or packet[IP].dport == 80 or packet[IP].sport == 80 or packet[IP].sport == 80):
            httpCount+=1
        elif IP in packet and (packet[IP].dport == 443 or packet[IP].dport == 443 or packet[IP].sport == 443 or packet[IP].sport == 443):
            httpsCount+=1


sniffer = Sniffer()

print("[*] Sniffer initialized...")
sniffer.start()

try:
    while True:
        sleep(100)

except KeyboardInterrupt as e:
    print("[*] Sniffing stopped.")
    print("ARP Count: " + str(arpCount))
    print("DHCP Count: " + str(dhcpCount))
    print("FTP Count: " + str(ftpCount))
    print("HTTP Count: " + str(httpCount))
    print("HTTPS Count: " + str(httpsCount))
