import netifaces
from scapy.layers.l2 import getmacbyip
from scapy.layers.dot11 import Ether
import socket


def get_self_ifo():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    mac = Ether().src
    return ip,hostname,mac



def getway():
    c = netifaces.gateways()
    gate = c["default"][2][0]
    gate_mac = getmacbyip(gate)
    return c["default"][2][0],gate_mac

if __name__ == "__main__":
    print(getway())
    print(get_self_ifo()[0])