import netifaces
from scapy.layers.l2 import getmacbyip




def getway():
    c = netifaces.gateways()
    gate = c["default"][2][0]
    gate_mac = getmacbyip(gate)
    return c["default"][2][0],gate_mac

if __name__ == "__main__":
    print(getway())