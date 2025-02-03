from scapy.all import rdpcap, Packet
import argparse

def physical_layer_parse(packet: Packet):
    """Parse out the physical layer of the packet
        Gets Packet size
    Args:
        packet (Packet): The packet
    """
    return

def link_layer_parse(packet: Packet):
    """Parse out the link layer of the packet
        Gets Destination MAC address, source MACaddress, and Ethertype
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
    for packet in scapy_cap:
        print(packet)
        
def parse_args():
    """Parses the arguments
    Returns:
        arguments
    """
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    
    # Input pcap file from Wireshark
    parser.add_argument("-r", "--file", type=str, required=True, help="Read from given pcap file")
    # All the filtering arguments
    parser.add_argument("filter", nargs="?", choices=["host", "port", "ip", "tcp", "udp", "icmp"],
                        help="Filters to apply on packets")
    parser.add_argument("filter_info", nargs="?", type=str, help="Additional info for the filter criteria. Ex IP or port")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture")
    parser.add_argument("-net", "--net", type=str, help="Filter IPs that are from or going to network")
    
    return parser.parse_args()

def main():
    """The main function to run the rest of the program."""
    args = parse_args()
    pcap_file = args.file
    packet_filter = args.filter
    filter_info = args.filter_info
    net = args.net
    packet_count = args.count
    
    print(pcap_file, packet_filter, filter_info, net, packet_count)
    return

if __name__ == "__main__":
    main()

