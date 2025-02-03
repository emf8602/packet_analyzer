from helper_functions import ProtocolNumber, flag_parse

class PacketClass:
  """The class to contain a packet
  Called PacketClass because of naming conflict between scapy's Packet 
  """
  def __init__(self, packet):
    """Constructor for PacketClass
    Args:
        packet : Data from scapy read_pcap function
    """
    self.packet = packet
    self.ether_layer = None
    self.ip_layer = None
    self.tcp_layer = None
    self.icmp_layer = None
    
    if packet.haslayer("Ether"):
        self.ether_layer = packet["Ether"]

        if packet.haslayer("IP"):
            self.ip_layer = packet["IP"]

            if packet.haslayer("TCP"):
                self.tcp_layer = packet["TCP"]
            
            elif packet.haslayer("UDP"):
                self.udp_layer = packet["UDP"]
            
            elif packet.haslayer("ICMP"):
                self.icmp_layer = packet["ICMP"]

  def parse_ethernet_layer(self):
    """Print out the ethernet layer if it exists
    """
    if self.packet.haslayer("Ether"):
      print("Ethernet Layer:")
      print(f"Packet Size: {len(self.packet)} bytes")
      print(f"Destination MAC Address: {self.ether_layer.dst}")
      print(f"Source MAC Address: {self.ether_layer.src}")
      print(f"Ethertype: {hex(self.ether_layer.type)}")
    else:
      print("No Ethernet layer")
  
  def parse_ip_layer(self):
    """Print out IP layer if it exists
    """
    if self.packet.haslayer("IP"):
      print("\nIP Layer:")
      print(f"Version: {self.ip_layer.version}")
      print(f"Header Length: {self.ip_layer.ihl * 4} bytes ({self.ip_layer.ihl})")
      print(f"Type of Service: {self.ip_layer.tos}")
      print(f"Total Length: {self.ip_layer.len}")
      print(f"Identification: {hex(self.ip_layer.id)} ({self.ip_layer.id})")
      print(f"Flags: {flag_parse(self.ip_layer.flags)}")
      print(f"Fragment Offset: {self.ip_layer.frag}")
      print(f"Time to Live (TTL): {self.ip_layer.ttl}")
      print(f"Protocol: {ProtocolNumber(self.ip_layer.proto).name} ({self.ip_layer.proto})")
      print(f"Header Checksum: {hex(self.ip_layer.chksum)}")
      print(f"Source IP Address: {self.ip_layer.src}")
      print(f"Destination IP Address: {self.ip_layer.dst}")
    else:
      print("\nNo IP layer")
    
  def parse_tcp_layer(self):
    """Print out TCP layer if it exists
    """
    if self.packet.haslayer("TCP"):
      print("\nTCP Layer:")
      print(f"Source Port: {self.tcp_layer.sport}")
      print(f"Destination Port: {self.tcp_layer.dport}")
      print(f"Sequence Number (raw): {self.tcp_layer.seq}")
      print(f"Acknowledgment Number (raw): {self.tcp_layer.ack}")
      print(f"Flags: {flag_parse(self.tcp_layer.flags)}")
      print(f"Window Size: {self.tcp_layer.window}")
      print(f"Checksum: {hex(self.tcp_layer.chksum)}")
    # else:
    #   print("\nNo TCP Layer")
    
  def parse_udp_layer(self):
    """Print out UDP layer if it exists"""
    if self.packet.haslayer("UDP"):
      print("\nUDP Layer:")
      print(f"Source Port: {self.udp_layer.sport}")
      print(f"Destination Port: {self.udp_layer.dport}")
      print(f"Length: {self.udp_layer.len}")
      print(f"Checksum: {hex(self.udp_layer.chksum)}")
    # else:
    #   print("\nNo UPD layer")
    
  def parse_icmp_layer(self):
    """Print out ICMP layer if it exists
    """
    if self.packet.haslayer("ICMP"):
      print("\nICMP Layer")
      print(f"Type: {self.icmp_layer.type}")
      print(f"Code: {self.icmp_layer.code}")
      print(f"Checksum: {hex(self.icmp_layer.chksum)}")
    # else:
    #   print("\nNo ICMP Layer")
    
  def valid_packet(self, packet_filter, filter_info, net):
    """Checks if the given packet is valid to be printed out
    Args:
        packet_filter (str|None): type of filter applied
        filter_info (str|None): extra info on filter
        net (str): The source or destination IP

    Returns:
        bool: True if packet is valid, false if not
    """
    if packet_filter:
        print(filter_info)
    if net:
        if net != self.packet.ip_layer.src and net != self.packet.ip_layer.dst:
            return False
    return True
  
  def print_layers(self):
    """Print all packet info layer by layer"""
    self.parse_ethernet_layer()
    self.parse_ip_layer()
    self.parse_tcp_layer()
    self.parse_udp_layer()
    self.parse_icmp_layer()
  