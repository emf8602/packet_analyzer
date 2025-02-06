# packet_analyzer
This program is a network packet analyzer called pktsniffer that reads packets and produces a detailed summary of those packets. The pktsniffer program first reads packets from a specified file (pcap file). Then it extracts and displays the different headers of the captured packets.

## What Data is Being Displayed
**Ethernet Header**: Packet size, Destination MAC address, Source MAC address, Ethertype  
**IP Header**: Version, Header length, Type of service, Total length, Identification, Flags, Fragment offset, Time to live, Protocol, Header checksum, Source and Destination IP addresses.  
**Encapsulated Packets**: TCP, UDP, or ICMP headers.

# How to Install Dependencies
First you need to install the added dependencies  
All the dependencies added were either scapy or related to Sphynx  
While in the projects directory run:
```cmd
pip install requirements.txt
```

# How to Run Program Via Commandline
How to use the program with flags on the commandline  

While in the repository containing `pktsniffer.py` run:
```cmd
python pktsniffer.py -r FILE [-host HOST] [-port PORT] [-ip] [-tcp] [-udp] [-icmp] [-c COUNT] [-net NET]
```
**Filter Arguments:**   
host *hostnameaddr*: True if either the IPv4/v6 source or destination of the packet is hostnameaddr.  
port *portnamenum*: True if either the source or destination port of the packet is portnamenum.  
ip: True if the packet is IPv4 packet.  
tcp: True where protocol is TCP.  
udp: True where protocol is UDP.  
icmp: True where protocol is ICMP.  
net *netnameaddr*: True if either the IPv4/v6 source or destination address of the packet has a network number of netnameaddr.  
**Other Arguments:**   
count *numbercount*: The number of packets to be analyzed

## Examples:
    python .\pktsniffer.py -r test.pcap -host 239.255.255.250  
Runs the pktsniffer program on the 'test.pcap' file and only showing packets where the source or destination has a host of 239.255.255.250  

    python .\pktsniffer.py -r test.pcap -c 5  
Runs the pktsniffer program on the 'test.pcap' file and only showing the first 5 packets in the file

    python .\pktsniffer.py -r test.pcap -port 53120  
Runs the pktsniffer program on the 'test.pcap' file and only showing the packets where the source or destination port = 53120

    python .\pktsniffer.py -r test.pcap -udp -c 5
Runs the pktsniffer program on the 'test.pcap' file only reading the first 5 packets and only displaying them if they use udp 

    python .\pktsniffer.py -r test.pcap -net 3.0
Runs the pktsniffer program on the 'test.pcap' file only showing the packets with a source or destination address of 3.xxx.xxx.xxx