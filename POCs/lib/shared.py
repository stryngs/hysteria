import sys
from scapy.all import *

class Shared(object):
    """Shared workspace"""

    def __init__(self, args):
        try:
            self.tgt = args[1]
            self.rtr = args[2]
            self.tIP = args[3]
            self.createMacs(self.tgt, self.rtr)
            self.kList = []
            self.vList = []
            for k, v in self.hDict.items():
                self.kList.append(k)
                self.vList.append(v)
        except Exception as E:
            print(E)
            sys.exit(1)

        ## Gen up a SynAck for the initial Virtual IP discovery
        self.vipFindPkt = '00 00 38 00 2F 40 40 A0 20 08 00 A0 20 08 00 00 89 B2 39 1A 04 00 00 00 12 16 85 09 A0 00 D9 00 00 00 00 00 00 00 00 00 2B B2 39 1A 00 00 00 00 16 00 11 03 D9 00 CA 01 88 02 75 00 AA BB CC DD EE FF 11 22 33 44 55 66 11 22 33 44 55 66 70 01 00 00 AA AA 03 00 00 00 08 00 45 00 00 3C 00 00 40 00 27 06 07 07 17 17 56 2C C0 A8 1E CA 00 50 B4 FA E1 17 41 5A CA 85 E5 D1 A0 12 71 20 44 00 00 00 02 04 05 B4 04 02 08 0A 38 DC 54 1B 14 06 1D 08 01 03 03 07 AD 2A 64 FB'


    def createMacs(self, tgt = 'aa:bb:cc:dd:ee:ff', rtr = '11:22:33:44:55:66'):
        """Who are we paying attention to"""
        hDict = {}
        hDict.update({'tgt': tgt})
        hDict.update({'rtr': rtr})
        self.hDict = hDict


    def ourHandler(self):
        def rip(pkt):
            """Trigger on RST"""
            if pkt[Dot11].addr1 == self.rtr:
                if pkt[Dot11].addr2 == self.tgt:
                    if pkt[Dot11].addr3 == self.rtr:
                        if pkt[IP].src == self.tIP:
                            if pkt[TCP].flags == 'R':
                                print('        ^ matching RST detected -- {0} appears vulnerable to CVE-2019-14899'.format(self.tgt))
                                return
            return None
        return rip


    def ourFilter(self):
        def rip(pkt):
            """Filter through our sniff"""

            ## All we care about is tgtMac and rtrMac at this pt
            if pkt[Dot11].addr1 in self.vList or pkt[Dot11].addr2 in self.vList or pkt[Dot11].addr3 in self.vList:

                ## Take the datas
                if pkt[Dot11].type == 2:

                    ## Grab only the TCPs
                    if pkt.haslayer(TCP):
                        print('TCP --> {0}'.format(pkt[TCP].flags))
                        return pkt

            ## Nothing in return!
            return None
        return rip
