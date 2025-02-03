from enum import Enum

class ProtocolNumber(Enum):
  """ Protocol Number Enum"""
  UDP = 17
  TCP = 6
  IGMP = 2

def flag_parse(flag_string: str):
  """Scapy gives flags as single chars, turn them to string
  Args:
      flag_string (str): A string of characters representing flag
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
