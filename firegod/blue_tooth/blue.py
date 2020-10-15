from bluepy.btle import Scanner, DefaultDelegate
from bluepy.btle import Peripheral ,UUID
class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewDev:
            print("Discovered device", dev.addr)
        elif isNewData:
            print("Received new data from", dev.addr)

scanner = Scanner().withDelegate(ScanDelegate())
devices = scanner.scan(10.0)

for dev in devices:
    print("Device %s (%s), RSSI=%d dB" % (dev.addr, dev.addrType, dev.rssi))
    for (adtype, desc, value) in dev.getScanData():
        print("  %s = %s" % (desc, value))

# p = Peripheral("be:58:60:02:97:88","public")
#
# dev_name_uuid = UUID(0x2A00)
# try:
#     ch = p.getCharacteristics(uuid=dev_name_uuid)[0]
#     if (ch.supportsRead()):
#         print(ch.read())
#
# finally:
#     p.disconnect()