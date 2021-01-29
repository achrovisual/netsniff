import signal
import socket, sys, os, re, time, netifaces
from scapy.all import *
import ipaddress
import collections

count = 0
def TCPPrint(pkt):
    global count
    count+=1
    ipSrc = ""
    ipDst = ""
    tcpSrc = ""
    tcpDst = ""
    if IP in pkt:
        ipSrc =pkt[IP].src
        ipDst =pkt[IP].dst
    if TCP in pkt:
        tcpSrc = pkt[TCP].sport
        tcpDst = pkt[TCP].dport
    print("IP SRC " + str(ipSrc) + " || TCP SRC PORT " + str(tcpSrc))
    print("IP DST " + str(ipDst) + " || TCP DST PORT " + str(tcpDst))
    print("==========================================================")
def HTTPPrint(pkt):
    httppkt = str(pkt)
    global count
    if IP in pkt:
        ipSrc =pkt[IP].src
        ipDst =pkt[IP].dst
    if TCP in pkt:
        tcpSrc = pkt[TCP].sport
        tcpDst = pkt[TCP].dport
    print("IP SRC " + str(ipSrc) + " || TCP SRC PORT " + str(tcpSrc))
    print("IP DST " + str(ipDst) + " || TCP DST PORT " + str(tcpDst))
    print("==========================================================")

    if httppkt.find('GET'):
        count+=1
    elif httppkt.find('PUT'):
        count+=1
    elif httppkt.find('POST'):
        count+=1
    elif httppkt.find('DELETE'):
        count+=1
    elif httppkt.find('PATCH'):
        count+=1

choice = input("Filter: [1] HTTP, [2] TCP, [3] ARP, [4] DHCP, [5] UDP")
y = sniff(count = 0, timeout=10, filter = "tcp", prn = HTTPPrint) #test function
print("Count: " + str(count))