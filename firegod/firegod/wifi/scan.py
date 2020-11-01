import random
import time
from scapy.all import *
from scapy.layers.all import *
from scapy.layers.dot11 import *
from scapy.layers.l2 import *
import pywifi
import pywifi.const as c
import sys
import firegod.wifi as firegod_wifi


class wifi_pywifi():
    def __init__(self):
        self.wifi = pywifi.PyWiFi()

    def wifi_scan_pywifi(self, num=0):
        """

        :param num 选择的网卡序列号 0-n:
        :return: list [{ssid: , mac: , signal: },{}...]
        return eg：[{'ssid': 'TP-LINK_5240', 'mac': '50:bd:5f:11:52:40:', 'signal': -34}, {'ssid': 'TP-LINK_5240', 'mac': '50:bd:5f:11:52:40:', 'signal': -34}]
        """

        wp = self.wifi.interfaces()[num]
        print(wp.name())
        wp.scan()
        resulut = wp.scan_results()
        wifi_list = []
        for i in resulut:
            temp_map = {}
            temp_map["ssid"] = i.ssid
            # bssid为mac地址
            temp_map["mac"] = i.bssid
            temp_map["signal"] = i.signal
            wifi_list.append(temp_map)
        return wifi_list


# 打印网卡的名字print(wp.name())
# 扫描wifi print([x.ssid for x in wp.scan_results()])

class wifi_scapy():
    mymap = []

    def __init__(self):
        pass

    # @staticmethod
    def call_back(self, pk):

        if pk.haslayer(Dot11Beacon):
            if pk.info not in self.mymap:
                # print(pk.show())
                self.mymap.append([pk.info, pk.addr2])
                print(pk.info.decode("utf-8"))
                print(pk.addr2)

    def scan_wifi(self,interface="wlan1mon"):
        if sys.platform == "win32":
            raise OSError("only support liunx, please use wifi_pywifi")
        sniff(iface=interface, prn=self.call_back)


# 获取目标 ap 的 mac 地址
def get_target_mac(ap_name):
    gun = wifi_pywifi()
    mylist = gun.wifi_scan_pywifi(0)
    for x in mylist:
        if x['ssid'] == ap_name:
            return x["mac"]



if __name__ == "__main__":
    firegod_wifi.go_monitor_airmion()
    a = wifi_scapy()
    a.scan_wifi()
