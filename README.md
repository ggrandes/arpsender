# ARP Sender

```
ARP-Sender 1.0, based on Hunt 1.5

Usage:
  -q             : quiet
  -v             : verbose
  -c count       : how many packets to send
  -w seconds     : how many seconds wait after sends
  -I device      : which ethernet device to use (eth0)
  -F eth-src-mac : ethernet source mac address
  -T eth-dst-mac : ehternet destination mac address
  -o opcode      : arp opcode
  -S arp-src-mac : arp sender mac address
  -s arp-src-ip  : arp sender ip address
  -D arp-dst-mac : arp target mac address
  -d arp-dst-ip  : arp target ip address

opcode strings: (ebtables -h arp)
1 = Request
2 = Reply
```

---
Inspired in [hunt](https://code.launchpad.net/ubuntu/+source/hunt) and [arping](https://github.com/iputils/iputils/blob/master/arping.c), this is a minimalistic version.
