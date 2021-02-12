# Author: Rafael Maderazo and Eugenio Pastoral
# Course: Data Communications

import socket, sys, netifaces
from scapy.all import *
from collections import *
from threading import Thread, Event
from time import sleep

# Declare variables for network statistics.
dhcp_count, http_count, https_count, arp_count, ftp_count, ssh_count = 0, 0, 0, 0, 0, 0
ip_list, mac_list = [], []

# This function gets the element with the most occurences in a list.
def most_frequent(List):
    occurence_count = Counter(List)
    return occurence_count.most_common(1)[0][0]

# This class sniffs the packets of the network.
class Sniffer(Thread):
    # This function initializes sniffer object.
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.socket = None
        self.stopper = Event()

    # This function starts the sniffing process of IP and ARP packets in the network.
    def run(self):
        self.socket = conf.L2listen(type=ETH_P_ALL, filter="ip or arp")
        sniff(opened_socket=self.socket, prn=self.check_handler, stop_filter=self.filter_stopper)

    # This function categorizes the packets and updates the counter variables.
    def check_handler(self, packet):
        global dhcp_count, http_count, https_count, arp_count, ftp_count, ssh_count

        # Check if the packet is a valid IP or ARP packet.
        if str(type(packet)) != "<class 'NoneType'>":
            # Check if a MAC address is present in the packet.
            if Ether in packet:
                # Append to list.
                mac_list.append(packet[Ether].src)
                mac_list.append(packet[Ether].dst)

            # Check if an IPv4 address is present in the packet.
            if IP in packet:
                # Append to list.
                ip_list.append(packet[IP].src)
                ip_list.append(packet[IP].dst)

            # Check if the packet is an ARP packet and update the counter.
            if ARP in packet and (packet[ARP].op == 1 or packet[ARP].op == 2):
                arp_count += 1

            # Check if the packet is a DCHP packet and update the counter.
            elif IP in packet and (packet[IP].sport == 67 or packet[IP].dport == 68):
                dhcp_count += 1

            # Check if the packet is a FTP packet and update the counter.
            elif IP in packet and (packet[IP].dport == 20 or packet[IP].dport == 21 or packet[IP].sport == 20 or packet[IP].sport == 21):
                ftp_count += 1

            # Check if the packet is a HTTP packet and update the counter.
            elif IP in packet and (packet[IP].dport == 80 or packet[IP].sport == 80):
                http_count += 1

            # Check if the packet is a HTTPS packet and update the counter.
            elif IP in packet and (packet[IP].dport == 443 or packet[IP].sport == 443):
                https_count += 1

            # Check if the packet is a SSH packet and update the counter.
            elif IP in packet and (packet[IP].dport == 22 or packet[IP].sport == 22):
                ssh_count += 1

            try:
                print("[!] New Packet: {src} : {sport} -> {dst} : {dport}".format(src = packet[IP].src, dst = packet[IP].dst, sport = packet[IP].sport, dport = packet[IP].dport))
            except IndexError as e:
                print("[!] ARP packet detected.")
            except:
                pass

    # This function stops the filter.
    def filter_stopper(self, packet):
        return self.stopper.isSet()

    # This function joins the threads.
    def join(self, timeout=None):
        self.stopper.set()
        super().join(timeout)

    # This function prints and dumps the result to the file.
    def print_dump(self, filename):
        # Print result to console.
        print("****Protocol Statistics:****")
        print("ARP Count: " + str(arp_count))
        print("DHCP Count: " + str(dhcp_count))
        print("FTP Count: " + str(ftp_count))
        print("HTTP Count: " + str(http_count))
        print("HTTPS Count: " + str(https_count))
        print("SSH Count: " + str(ssh_count))

        print("\nTop IP address: " + str(most_frequent(ip_list)))
        print("Top IP address: " + str(most_frequent(mac_list)))

        # Reopen the dump file/
        f = open(filename, "a")

        # Append the results to the dump file.
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

    # This function initializes the sniffer thread.
    def initialize(self):
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
