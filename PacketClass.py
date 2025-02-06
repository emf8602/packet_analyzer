import re

from helper_functions import ProtocolNumber, flag_parse


class PacketClass:
  """The class to contain a packet.
  Called PacketClass because of naming conflict between scapy's Packet.
  """
  def __init__(self, packet, number: int):
    """Constructor for PacketClass.
    Args:
        packet : Data from scapy read_pcap function.
        number (int): The number of packet being analyzed.
    """
    self.packet = packet
    self.number = number
    self.ether_layer = None
    self.ip_layer = None
    self.tcp_layer = None
    self.udp_layer = None
    self.icmp_layer = None
    
    if packet.haslayer("Ether"):
      self.ether_layer = packet["Ether"]
      if packet.haslayer("IP") or packet.haslayer("IPv6"):
        if packet.haslayer("IP"):
          self.ip_layer = packet["IP"]
        else:
          self.ip_layer = packet["IPv6"]
        if packet.haslayer("TCP"):
          self.tcp_layer = packet["TCP"]
        elif packet.haslayer("UDP"):
          self.udp_layer = packet["UDP"]
        elif packet.haslayer("ICMP"):
          self.icmp_layer = packet["ICMP"]

  def parse_ethernet_layer(self):
    """Print out the ethernet layer if it exists."""
    if self.packet.haslayer("Ether"):
      print("Ethernet Layer:")
      print(f"Packet Size: {len(self.packet)} bytes")
      print(f"Destination MAC Address: {self.ether_layer.dst}")
      print(f"Source MAC Address: {self.ether_layer.src}")
      print(f"Ethertype: {hex(self.ether_layer.type)}")
    else:
      print("No Ethernet layer")
  
  def parse_ip_layer(self):
    """Print out IP layer if it exists."""
    if self.ip_layer:
      print("\nIP Layer:")
      print(f"Version: {self.ip_layer.version}")
      if self.ip_layer.version == 4:
        header_length = self.ip_layer.ihl
        print(f"Header Length: {header_length*4} bytes ({header_length})")
        print(f"Type of Service: {self.ip_layer.tos}")
        print(f"Total Length: {self.ip_layer.len}")
        ip_id = self.ip_layer.id
        print(f"Identification: {hex(ip_id)} ({ip_id})")
        print(f"Flags: {flag_parse(self.ip_layer.flags)}")
        print(f"Fragment Offset: {self.ip_layer.frag}")
        print(f"Time to Live (TTL): {self.ip_layer.ttl}")
        proto_name = ProtocolNumber(self.ip_layer.proto).name
        print(f"Protocol: {proto_name} ({self.ip_layer.proto})")
        print(f"Header Checksum: {hex(self.ip_layer.chksum)}")
      print(f"Source IP Address: {self.ip_layer.src}")
      print(f"Destination IP Address: {self.ip_layer.dst}")
    else:
      print("\nNo IP layer")
    
  def parse_tcp_layer(self):
    """Print out TCP layer if it exists."""
    if self.tcp_layer:
      print("\nTCP Layer:")
      print(f"Source Port: {self.tcp_layer.sport}")
      print(f"Destination Port: {self.tcp_layer.dport}")
      print(f"Sequence Number (raw): {self.tcp_layer.seq}")
      print(f"Acknowledgment Number (raw): {self.tcp_layer.ack}")
      print(f"Flags: {flag_parse(self.tcp_layer.flags)}")
      print(f"Window Size: {self.tcp_layer.window}")
      print(f"Checksum: {hex(self.tcp_layer.chksum)}")
    
  def parse_udp_layer(self):
    """Print out UDP layer if it exists."""
    if self.udp_layer:
      print("\nUDP Layer:")
      print(f"Source Port: {self.udp_layer.sport}")
      print(f"Destination Port: {self.udp_layer.dport}")
      print(f"Length: {self.udp_layer.len}")
      print(f"Checksum: {hex(self.udp_layer.chksum)}")
    
  def parse_icmp_layer(self):
    """Print out ICMP layer if it exists."""
    if self.icmp_layer:
      print("\nICMP Layer")
      print(f"Type: {self.icmp_layer.type}")
      print(f"Code: {self.icmp_layer.code}")
      print(f"Checksum: {hex(self.icmp_layer.chksum)}")
    
  def valid_packet(self, host, port, bool_filter, net):
    """Checks if the given packet is valid to be printed out
    Args:
        host (str): Optional flag to filter packets based on host.
        port (str): Optional flag to filter packets based on port.
        bool_filter (list): Optional list of boolean filters
          Can contain "ip", "tcp", "udp", and or "icmp"
        net (str): Optional flag for source or destination IP.
    Returns:
        bool: True if packet is valid, false if it is not.
    """
    if host is not None:
      if self.ip_layer is not None:
        if host != self.ip_layer.dst and host != self.ip_layer.src:
          return False
      else:
        return False
    if port is not None:
      port = int(port)
      if self.tcp_layer is not None:
        if port != self.tcp_layer.sport and port != self.tcp_layer.dport:
          return False
      elif self.udp_layer is not None:
        if port != self.udp_layer.sport and port != self.udp_layer.dport:
          return False
      else:
        return False
    if bool_filter is not None and "ip" in bool_filter:
      if not self.ip_layer or self.ip_layer.version != 4:
        return False
    if bool_filter is not None and "tcp" in bool_filter:
      if not self.tcp_layer:
        return False
    elif bool_filter is not None and "udp" in bool_filter:
      if not self.udp_layer:
        return False
    elif bool_filter is not None and "icmp" in bool_filter:
      if not self.icmp_layer:
        return False
    if net is not None:
      net_split = re.split('\.|:', net)
      if net_split[-1] == '0':
        #This is not an exact match
        src_split = re.split('\.|:', self.ip_layer.src)
        dst_split = re.split('\.|:', self.ip_layer.dst)

        for count, split in enumerate(net_split[:-1]):
          if split != src_split[count] and split != dst_split[count]:
            return False
      else:
        if net != self.ip_layer.src and net != self.ip_layer.dst:
          return False
    return True
  
  def print_layers(self):
    """Print all packet info layer by layer."""
    print(f"\n----------Packet Number {self.number}----------")
    self.parse_ethernet_layer()
    self.parse_ip_layer()
    self.parse_tcp_layer()
    self.parse_udp_layer()
    self.parse_icmp_layer()
  