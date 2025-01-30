from scapy.all import rdpcap, Packet

def main():
    """The main function to run the rest of the program."""
    read_pcap("home.pcap")
    return

def physical_layer_parse(packet: Packet):
    """Parse out the physical layer of the packet
    Args:
        packet (Packet): The packet
    """
    return

def link_layer_parse(packet: Packet):
    """Parse out the link layer of the packet
    Args:
        packet (Packet): The packet
    """
    return

def network_layer_parse(packet: Packet):
    """Parse out the network layer of the packet
    Args:
        packet (Packet): The packet
    """
    return

def transport_layer_parse(packet: Packet):
    """Parse out the transport layer of the packet
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

if __name__ == "__main__":
    main()

