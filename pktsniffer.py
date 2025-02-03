from enum import Enum
from scapy.all import rdpcap, Packet
import argparse

class ProtocolNumber(Enum):
    UDP = 17
    TCP = 6
    IGMP = 2

def flag_parse(flag_string: str):
    """_summary_
    Args:
        flag_string (str): A string of characters repre
    Return:
        String that are the flags used 
    """
    flag_array = []
    for char in flag_string:
        if char == "F":
            flag_array.append("FIN")
        elif char == "A":
            flag_array.append("ACK")
        elif char == "P":
            flag_array.append("PSH")
    return ", ".join(flag_array)
            

def physical_layer_parse(packet: Packet):
    """Parse out the physical layer of the packet
        Gets Packet size
    Args:
        packet (Packet): The packet
    """
    return

def link_layer_parse(packet: Packet):
    """Parse out the link layer of the packet 
    called Ethernet layer 
    Args:
        packet (Packet): The packet
    """
    return

def network_layer_parse(packet: Packet):
    """Parse out the network layer of the packet
        Gets version, header length, type of service, total length, ID, flags,
        fragment offset, time to live, protocol, header checksum,
        source IP address, destination IP address
    Args:
        packet (Packet): The packet
    """
    return

def transport_layer_parse(packet: Packet):
    """Parse out the transport layer of the packet
        Gets TCP, UDP, or ICMP headers.
    Args:
        packet (Packet): The packet
    """
    return

def application_layer_parse(packet: Packet):
    """Parse out the application layer of the packet
    Args:
        packet (Packet): The packet
    """
    return

def read_pcap(filename):
    """Reads the pcap file byte by byte
    Args:
        filename String: the name of the pcap file
    """
    scapy_cap = rdpcap(filename)
    for count, packet in enumerate(scapy_cap, start=1):
        print(f"\n----------Packet number {count}----------")  
        if packet.haslayer("Ether"):
            ether_layer = packet["Ether"]
            print("Ethernet Layer")
            
            print(f"Packet Size: {len(packet)} bytes")
            print(f"Destination MAC Address: {ether_layer.dst}")
            print(f"Source MAC Address: {ether_layer.src}")
            print(f"Ethertype: {hex(ether_layer.type)}")

            if packet.haslayer("IP"):
                ip_layer = packet["IP"]
                print("\nIP Layer")
                
                print(f"Version: {ip_layer.version}")
                print(f"Header Length: {ip_layer.ihl * 4} bytes ({ip_layer.ihl})")
                print(f"Type of Service: {ip_layer.tos}")
                print(f"Total Length: {ip_layer.len}")
                print(f"Identification: {hex(ip_layer.id)} ({ip_layer.id})")
                print(f"Flags: {flag_parse(ip_layer.flags)}")
                print(f"Fragment Offset: {ip_layer.frag}")
                print(f"Time to Live (TTL): {ip_layer.ttl}")
                print(f"Protocol: {ProtocolNumber(ip_layer.proto).name} ({ip_layer.proto})")
                print(f"Header Checksum: {hex(ip_layer.chksum)}")
                print(f"Source IP Address: {ip_layer.src}")
                print(f"Destination IP Address: {ip_layer.dst}")

                if packet.haslayer("TCP"):
                    tcp_layer = packet["TCP"]
                    print("\nTCP Layer")
                    print(f"Source Port: {tcp_layer.sport}")
                    print(f"Destination Port: {tcp_layer.dport}")
                    print(f"Sequence Number (raw): {tcp_layer.seq}")
                    print(f"Acknowledgment Number (raw): {tcp_layer.ack}")
                    print(f"Flags: {flag_parse(tcp_layer.flags)}")
                    print(f"Window Size: {tcp_layer.window}")
                    print(f"Checksum: {hex(tcp_layer.chksum)}")
                
                elif packet.haslayer("UDP"):
                    udp_layer = packet["UDP"]
                    print("\nUDP Layer")
                    print(f"Source Port: {udp_layer.sport}")
                    print(f"Destination Port: {udp_layer.dport}")
                    print(f"Length: {udp_layer.len}")
                    print(f"Checksum: {hex(udp_layer.chksum)}")
                
                elif packet.haslayer("ICMP"):
                    icmp_layer = packet["ICMP"]
                    print("\nICMP Layer")
                    print(f"Type: {icmp_layer.type}")
                    print(f"Code: {icmp_layer.code}")
                    print(f"Checksum: {hex(icmp_layer.chksum)}")
            else:
                print("\nIP layer does not exist")
        else:
            print("\nEthernet layer does not exist")
        
def parse_args():
    """Parses the arguments
    Returns:
        arguments
    """
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    
    parser.add_argument("-r", "--file", type=str, required=True, help="Read from given pcap file")
    parser.add_argument("filter", nargs="?", choices=["host", "port", "ip", "tcp", "udp", "icmp"],
                        help="Filters to apply on packets")
    parser.add_argument("filter_info", nargs="?", type=str, help="Additional info for the filter criteria. Ex IP or port")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture")
    parser.add_argument("-net", "--net", type=str, help="Filter IPs that are from or going to network")
    
    return parser.parse_args()

def main():
    """The main function to run the rest of the program."""
    args = parse_args()
    pcap_file: str = args.file
    packet_filter: str = args.filter
    filter_info: str = args.filter_info
    net: str = args.net
    packet_count: int = args.count
    
    print(pcap_file, packet_filter, filter_info, net, packet_count)
    return

if __name__ == "__main__":
    main()
    read_pcap("home.pcap")

