from scapy.all import rdpcap
import argparse
from PacketClass import PacketClass

def read_pcap(filename, packet_count=None):
    """Reads the pcap file, parsed via scapy
    Args:
        filename String: the name of the pcap file
        packet_count int: The limit of packets analyzed
    Returns:
        packets Packet[]: The array of packets read
    """
    scapy_cap = rdpcap(filename)
    packets = []
    for packet in scapy_cap[:packet_count]:
        current_packet = PacketClass(packet)
        packets.append(current_packet)
    return packets
    
def parse_args():
    """Parses the arguments
    Returns:
        arguments
    """
    parser = argparse.ArgumentParser(description="Display and Filter a Packet Sniffing File")
    
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
        
    packets = read_pcap(pcap_file, packet_count)
    filtered_packets = [
        packet for packet in packets 
        if packet.valid_packet(packet_filter, filter_info, net)
    ]
    
    for count, filtered_packet in  enumerate(filtered_packets, start=1):
        print(f"\n----------Packet Number {count}----------")
        filtered_packet.print_layers()
    return

if __name__ == "__main__":
    main()