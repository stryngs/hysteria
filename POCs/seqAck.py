#!/usr/bin/python

from scapy.all import *
import sys

def pFilter(ourFilter):
    def snarf(packet):
        if packet[IP].src == sys.argv[1]:
            x = packet[TCP].seq
            y = packet[TCP].ack
            a = packet[TCP].sport
            b = packet[TCP].dport
            print('{0} -- {1} - {2}   -> {3} '.format(x, y, a, b ))
        else:
            x = packet[TCP].ack
            y = packet[TCP].seq
            a = packet[TCP].sport
            b = packet[TCP].dport
            print('{0} -- {1} - {2} <- {3}'.format(x, y, a, b))  ## Yes formatting would help...

    return snarf

if __name__ == '__main__':
    PRN = pFilter('ICMP')
    bpF = 'ip and host {0}'.format(sys.argv[2])
    p = sniff(iface = sys.argv[1], prn = PRN, filter = bpF)
