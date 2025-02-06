import argparse

from scapy.all import rdpcap
from PacketClass import PacketClass


def read_pcap(filename, packet_count=None):
    """Reads the pcap file, parsed via scapy
    Args:
        filename (str): the name of the pcap file
        packet_count (int): The limit of packets analyzed
    Returns:
        packets (Packet[]): The array of packets read
    """
    scapy_cap = rdpcap(filename)
    packets = []
    for count, packet in enumerate(scapy_cap[:packet_count], start=1):
        current_packet = PacketClass(packet, count)
        packets.append(current_packet)
    return packets
    
def parse_args():
    """Parses the arguments
    Explanation of the arguments from PCAP-FILTER(7) MAN PAGES.
        host hostnameaddr: True if either the IPv4/v6 
            source or destination of the packet is hostnameaddr.
        port portnamenum: True if either the 
            source or destination port of the packet is portnamenum.
        ip: True if the packet is IPv4 packet.
        tcp: True where protocol is TCP.
        udp: True where protocol is UDP.
        icmp: True where protocol is ICMP.
        net netnameaddr: True if either the IPv4/v6 
            source or destination address of the packet 
            has a network number of netnameaddr.
    Returns:
        arguments: Namespace
    """
    parser = argparse.ArgumentParser(
        description="Display and Filter a Packet Sniffing File"
        )
    parser.add_argument(
        "-r", "--file",
        type=str, required=True,
        help="Read from given pcap file"
        )
    parser.add_argument(
        "-host", "--host",
        type=str, help="Filter packet by destination"
        )
    parser.add_argument(
        "-port", "--port",
        type=str, help="Filter packet by source port")
    
    parser.add_argument(
        "-ip", 
        action = "store_true", 
        help="Filter by ipv4"
    )
    parser.add_argument(
        "-tcp", 
        action = "store_true", 
        help="Filter by tcp"
    )
    parser.add_argument(
        "-udp", 
        action = "store_true", 
        help="Filter by udp"
    )
    parser.add_argument(
        "-icmp", 
        action = "store_true", 
        help="Filter by icmp"
    )
    parser.add_argument(
        "-c", "--count",
        type=int, help="Number of packets to capture"
        )
    parser.add_argument(
        "-net", "--net",
        type=str, help="Filter IPs that are from or going to network"
        )
    return parser.parse_args()

def main():
    """The main function to run the entire program."""
    args = parse_args()
    pcap_file: str = args.file
    host: str = args.host
    port: str = args.port
    net: str = args.net
    packet_count: int = args.count
    ip_flag: bool = args.ip
    tcp_flag: bool = args.tcp
    udp_flag: bool = args.udp
    icmp_flag: bool = args.icmp
    
        
    packets = read_pcap(pcap_file, packet_count)
    filtered_packets = [
        packet for packet in packets 
        if packet.valid_packet(
            host, port, net, ip_flag, 
            tcp_flag, udp_flag, icmp_flag
            )
        ]
    for filtered_packet in filtered_packets:
        filtered_packet.print_layers()
    return

if __name__ == "__main__":
    main()