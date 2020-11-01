"""
sudo+ssh://pi@192.168.43.192:22/usr/bin/python3.7 -u /tmp/pycharm_project_955/wifimonitor.py
308
50:0f:f5:cf:ae:70
DIRECT-27404DCC
fa:d0:27:40:cd:cc
Honor 8X
88:f5:6e:92:91:a7
way
74:05:a5:d6:bc:05
iso
0e:28:ff:a0:40:6d
TP-LINK_C838
14:75:90:8c:c8:38
vivo S7
36:80:c6:0b:08:21
^C
进程已结束，退出代码 129

"""
import time
from scapy.all import *
from scapy.layers.all import *
from scapy.layers.dot11 import *
from scapy.layers.l2 import *

interface = "wlan1mon"



mac = []
pkbase = []
for i in range(50):
    a = RandMAC()

    pkbase.append(RadioTap() / Dot11(subtype=8, addr1=a, addr2="FF:FF:FF:FF:FF:FF",
                            addr3=a) / Dot11Beacon(cap="ESS"))
ssid=[str(x)+"FREE CSLG" for x in range(50)]
ssid_elt=[pkbase[x]/Dot11Elt(ID='SSID',info=ssid[x],len=len(ssid[x])) for x in range(50)]
# ssid_elt2=[Dot11Elt(ID='SSID',info="dad",len=len("dad")) for x in range(100)]
# rsn = Dot11Elt(ID='RSNinfo', info=(
#     '\x01\x00'  # RSN Version 1
#     '\x00\x0f\xac\x02'  # Group Cipher Suite : 00-0f-ac TKIP
#     '\x02\x00'  # 2 Pairwise Cipher Suites (next two lines)
#     '\x00\x0f\xac\x04'  # AES Cipher
#     '\x00\x0f\xac\x02'  # TKIP Cipher
#     '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
#     '\x00\x0f\xac\x02'  # Pre-Shared Key
#     '\x00\x00'))  # RSN Capabilities (no extra capabilities)

while 1:
    # for x in range(100):
    #     sendp(pkbase/ssid_elt2[0],iface=interface,inter=0.001,count=5)
    # time.sleep(0.5)
    for x in range(49):
        sendp(ssid_elt[x],iface=interface, inter=0, count=2)
    # sniff(iface = interface,prn=call_b)
