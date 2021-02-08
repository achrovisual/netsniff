import signal
import socket, sys, os, re, time, netifaces
from scapy.all import *
import ipaddress
from collections import *
from threading import Thread, Event
from time import sleep

dhcp_count, http_count, https_count, arp_count, ftp_count, ssh_count = 0, 0, 0, 0, 0, 0
ip_list, mac_list = [], []

def most_frequent(List):
    occurence_count = Counter(List)
    return occurence_count.most_common(1)[0][0]

class Sniffer(Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.socket = None
        self.stopper = Event()

    def run(self):
        self.socket = conf.L2listen(type=ETH_P_ALL, filter="ip or arp")

        sniff(opened_socket=self.socket, prn=self.check_handler, stop_filter=self.filter_stopper)

    def check_handler(self, packet):
        global dhcp_count, http_count, https_count, arp_count, ftp_count, ssh_count
        if str(type(packet)) != "<class 'NoneType'>":
            if Ether in packet:
                srcMAC = packet[Ether].src
                dstMAC = packet[Ether].dst

                mac_list.append(srcMAC)
                mac_list.append(dstMAC)

            if IP in packet:
                srcIP = packet[IP].src
                dstIP = packet[IP].dst

                ip_list.append(srcIP)
                ip_list.append(dstIP)


            if ARP in packet and (packet[ARP].op == 1 or packet[ARP].op == 2):
                arp_count += 1
            elif IP in packet and (packet[IP].sport == 67 or packet[IP].dport == 68):
                dhcp_count += 1
            elif IP in packet and (packet[IP].dport == 20 or packet[IP].dport == 21 or packet[IP].sport == 20 or packet[IP].sport == 21):
                ftp_count += 1
            elif IP in packet and (packet[IP].dport == 80 or packet[IP].sport == 80):
                http_count += 1
            elif IP in packet and (packet[IP].dport == 443 or packet[IP].sport == 443):
                https_count += 1
            elif IP in packet and (packet[IP].dport == 22 or packet[IP].sport == 22):
                ssh_count += 1

            print("[!] New Packet: {src} : {sport} -> {dst} : {dport}".format(src = srcIP, dst = dstIP, sport = packet[IP].sport, dport = packet[IP].dport))

    def filter_stopper(self, packet):
        return self.stopper.isSet()

    def join(self, timeout=None):
        self.stopper.set()
        super().join(timeout)

    def print_dump(self, filename):
        print("\n\n\n[*] Sniffing stopped.\n")
        print("****Protocol Statistics:****\n")
        print("ARP Count: " + str(arp_count))
        print("DHCP Count: " + str(dhcp_count))
        print("FTP Count: " + str(ftp_count))
        print("HTTP Count: " + str(http_count))
        print("HTTPS Count: " + str(https_count))
        print("SSH Count: " + str(ssh_count))

        print("\nTop IP address: " + str(most_frequent(ip_list)))
        print("Top IP address: " + str(most_frequent(mac_list)))

        f = open(filename, "a")
        f.write("****Protocol Statistics****\n")

        f.write("ARP Count: " + str(arp_count))
        f.write("\nDHCP Count: " + str(dhcp_count))
        f.write("\nFTP Count: " + str(ftp_count))
        f.write("\nHTTP Count: " + str(http_count))
        f.write("\nHTTPS Count: " + str(https_count))
        f.write("\nSSH Count: " + str(ssh_count))

        f.write("\n\n****Top Conversations****\n")
        f.write("Top IP address: " + str(most_frequent(ip_list)))
        f.write("\nTop MAC address: " + str(most_frequent(mac_list)))

    def initialize(self):
        # sniffer = Sniffer()

        print("[*] Sniffer initialized...")
        print("***Use CTRL + C to end sniffing.***")
        sleep(2.0)
        self.start()

        try:
            while True:
                sleep(100)

        except KeyboardInterrupt as e:
            self.join()
            # self.print_dump()
            if self.is_alive():
                self.socket.close()
                sys.exit(0)
