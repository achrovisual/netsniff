# netsniff
Simple Python program that scans the network and dumps the results into a file. This program uses Scapy. It can get the IP and MAC mappings and the protocol statistics of the network.

# Network Scanning
The network scan performs an ARP scan to get the IP address and MAC address mappings. To get the protocol statistics, it sniffs through the packets inside the network. The syntax for performing the network scan is as follows:
```
sudo ptyhon3 netsniff.py -i [interface]
```

# Arguments
These are the following arguments the program can use.
### Required Arguments
| Argument  | Description |
| ------------- | ------------- |
| -i  | Network Interface to be used  |
