# Author: Rafael Maderazo and Eugenio Pastoral
# Course: Data Communications

import ipcalc, sniffer, argparse, sys, netifaces
from datetime import datetime
from scapy.all import *

try:
    from scapy.all import *
except ImportError:
    print("Scapy library for Python is not installed on your system. Run 'pip install --pre scapy[basic]' to install the library.")
    print("For more information, visit https://scapy.readthedocs.io/en/latest/installation.html to isntall Scapy.")
    exit(0)

# Declare sniffer object
sniff = sniffer.Sniffer()

# Get current date and time for the filename of the dump file
now = datetime.now()
dt_string = now.strftime("%Y-%m-%d %H.%M.%S")
filename = "netsniff_dump " + dt_string + ".txt"

# This function scans the network through sending ARP packets. The result is the IP:MAC mapping of the devices in the network. It takes in an IPv4 address as a parameter.
def arp_scan(ip):
    try:
        # Print console message.
        print("[*] Scanning " + ip + "...")

        # Initialize the packet.
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        # Send out the packet.
        ans, unans = srp(request, timeout=2, iface='ens18', inter=0.1, verbose = 0)

        # Initialize result list.
        result = []

        # Create the dump file.
        f = open(filename, "w")
        f.write("****IP:MAC Mapping****\n")

        # Get the IPv4 and MAC addresses in each response packet.
        for sent, received in ans:
            # Write the IPv4 and MAC addresses into the dump file.
            f.write("IP: " + str(received.psrc) + " | MAC: " + str(received.hwsrc) + "\n")

            # Store the IPv4 and MAC addresses into the result list.
            client = {'IP': received.psrc, 'MAC': received.hwsrc}
            result.append(client)

        # If no mapping is found, write it in the dump file.
        if result == []:
            f.write("None found.\n")

        f.write("\n")

        # Close file.
        f.close()

        return result

    except KeyboardInterrupt as e:
        sys.exit(0)

def main():
    # Argument Parsing
    parser = argparse.ArgumentParser(description = "To use netsniff, please indicate the network interface to be used. The syntax is as follows:\n'sudo python3 netscniff.py -i [network interface]'", formatter_class = argparse.RawTextHelpFormatter)
    parser.add_argument("-i", "--i", action = 'store_true', help = "Network Interface to be used")
    args = parser.parse_args()

    try:
        # Get the IPv4 address and subnet mask.
        ip = netifaces.ifaddresses(str(args.i))[netifaces.AF_INET][0]['addr']
        subnet = netifaces.ifaddresses(str(args.i))[netifaces.AF_INET][0]['netmask']

        # Convert IPv4 and subnet mask to CIDR format.
        addr = ipcalc.IP(ip, mask=subnet)

        # Perform ARP scan.
        arp_scan(str(addr.guess_network()))

        # Perform packet sniffing.
        sniff.initialize()

    except:
        print("Please provide a valid network interface. Try again.")

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
