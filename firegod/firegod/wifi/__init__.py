import time
from  scapy.all import *
from scapy.layers.all import *
from scapy.layers.dot11 import *
from scapy.layers.l2 import *
import os
def go_monotor(interface="wlan1"):
    os.system( "sudo " +"ifconfig"+ " " + interface + " " + "down")
    os.system("sudo " +"iwconfig" + " " + interface + " " + "mode" + " " + "-monitor")
    os.system("sudo " +"ifconfig" + " " + interface + " " + "up")
    pass

def go_monitor_airmion(interface="wlan1"):
    os.system("sudo airmon-ng start "+interface)
    pass


def go_managed():
    def go_monotor(interface="wlan1"):
        os.system("sudo " + "ifconfig" + " " + interface + " " + "down")
        os.system("sudo " + "iwconfig" + " " + interface + " " + "mode" + " " + "-managed")
        os.system("sudo " + "ifconfig" + " " + interface + " " + "up")
        pass

if __name__ == "__main__":
    go_monitor_airmion()