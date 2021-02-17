# In those immortal words
But wait, there's more.

# My two cents
Conclusions on the initial research as provided by
  ```
  "William J. Tolley" <william () breakpointingbad com>
  ```

## Pre-requisites
- https://github.com/stryngs/packetEssentials -- Install packetEssentials
- https://github.com/stryngs/802Eleven        -- frameTracer.py is here
- Scapy                                       -- Underlying useful library

## Useful syntax
```
python2 ./bSniff.py '<tgtMac>' '<rtrMac>' '<virtual IP>' '<sniffing NIC>'
python2 ./vipFind.py '<tgtMac>' '<rtrMac>' '<virtual IP>' '<injecting NIC>' '<Gateway IP of Wifi NIC from tgt>'
python2 ./seqAck.py '<sniffing NIC>' '<IP Address of server Tgt is connected to>'
python2 ./keepAlive.py <Desired to stay connected to> <Time to sleep -- recommend # is 2>
python2 ./frameTracer.py -i <Monitor Mode NIC> -x <Bob's wifi MAC> -y <Bob's AP MAC> -v
```
## How to RST a bit


## Prove it
First we need to ensure our Monitor Mode NICs act as expected.  To do this in the least painful way as possible, we use an Open Wifi environment.  Using a test machine (Bob) that has the OpenVPN client, connect to a server of your choice using keepAlive.py.  Bob should not be connected to the OpenVPN server just yet.

From Bob, execute seqAck.py and keepAlive.py.  From your machine (Alice), invoke Monitor Mode accordingly.  Once complete, run seqAck.py.

Align your shells and you will see how the SEQ and ACKs from Bob match the SEQ and ACKs sniffed by Alice (open-wifi_seq-acks.png).

If you have gotten this far, then you are ready to see how using VPN with encryption will defeat your intentions.

Now connect Bob to the OpenVPN server.  Then, after you've verified that Bob is behind the VPN, repeat the above with Bob.

As the SEQs and ACKs you see on Alice become muddled, we can use frameTracer.py to clear up any misconceptions.  You now need to switch the sniffing NIC on the Pi, to something like tun0.  In this way it sees the VPN traffic, and not wlan0 traffic.

With seqAck.py and keepAlive.py running on the Raspberry Pi, take note of the SEQs and ACKs.  Run frameTracer.py.  Once you've captured some of the traffic, open it up in Wireshark.  Using the filter string of "openvpn" will allow you to isolate the OpenVPN traffic.

## In closing
Yes, the outer SEQ and ACKs will match.  However, the VPN payload itself is undecipherable.  Without knowledge of the TCP SEQ and ACKs, you cannot inject successfully.  Let alone that you would have to decrypt the OpenVPN payload, modify what is in it, and then re-inject it.  Without a POC of how to decipher OpenVPN, we are stuck.

**This encryption is why even though this CVE exposed some changes that need to be made and discussions had; it in no way that I can see, exposes the VPN itself to TCP Injection.**
