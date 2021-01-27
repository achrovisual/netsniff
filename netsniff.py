from scapy.all import *
import ipaddress
import socket

def arp_scan(ip):
    try:
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

        ans, unans = srp(request, timeout=2, retry=1)
        result = []

        for sent, received in ans:
            client = {'IP': received.psrc, 'MAC': received.hwsrc}
            print(client)
            result.append(client)
        return result
    except KeyboardInterrupt as e:
        sys.exit(0)

if __name__ == '__main__':
    try:
        # host_name = socket.gethostname()
        # host_ip = socket.gethostbyname(host_name)

        # ip = ipaddress.ip_interface(host_ip + '/0.0.0.0')
        # ip = ipaddress.ip_interface('172.16.0.0/255.240.0.0')

        ip = input('Enter network address: ')

        print(arp_scan(ip))
    except KeyboardInterrupt as e:
        sys.exit(0)
