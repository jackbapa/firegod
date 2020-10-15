from scapy.all import *
from scapy.layers.inet import ICMP
from scapy.layers.l2 import *
from scapy.layers.dot11 import IP,TCP


c = Ether()
b = c/ICMP()
print(ls(b))
print(c.src)
