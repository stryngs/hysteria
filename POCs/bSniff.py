#!/usr/bin/python2

import sys
from lib import shared

from scapy.all import *

if __name__ == '__main__':
    sh = shared.Shared(sys.argv)

    ## Grab a handle
    pFilter = sh.ourFilter()
    pHandler = sh.ourHandler()

    """
    Running the below in an interactive IDE such as ipython allows you to hit
    crtl + c and then touch the object you just created, p.

    Will be useful for step 2 and beyond
    """
    try:
        p = sniff(iface = sys.argv[4], prn = pHandler, lfilter = pFilter)
    except Exception as E:
        print(E)
        sys.exit(1)
