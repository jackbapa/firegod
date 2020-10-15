import nmap.nmap as n
from firegod.scan import getway


def scan_by_gate(yanma = 24,arg="-sP"):
    nm = n.PortScanner()
    gate,_ = getway.getway()
    print(f"find gate -- {gate}")
    nm.scan(hosts=gate+"/"+str(yanma),arguments=arg)
    c = nm.all_hosts()
    return c

if __name__ =="__main__":
    print(getway.getway())
    a = scan_by_gate()
    print(a)