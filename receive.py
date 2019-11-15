#!/usr/bin/env python
import os
import sys
import struct
import pandas as pd

from threading import Thread
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, UDP, Raw, TCP
from scapy.layers.inet import _IPOption_HDR
from scapy.fields import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from net_topology import get_network, get_shorest_path, update_shorest_path
from protocols import SwitchTrace, MRI, SourceRoute

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def send_ack(pkt):
    iface = get_if()

    list_switches, dict_host_ip, dict_link_weight, dict_link_port = get_network ('ring')
    sp_nodes, sp_ports = get_shorest_path(dict_link_weight, dict_link_port, src = 'h2', dst = 'h1')

    ack = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff")
    j = 0
    for p in sp_ports:
        try:
            ack = ack / SourceRoute(bos=0, port=p)
            j = j+1
        except ValueError:
            pass
    if ack.haslayer(SourceRoute):
        ack.getlayer(SourceRoute, j).bos = 1     
    ack = ack / IP(dst=pkt[IP].src, proto=17) / UDP(dport=4322, sport=1235) / MRI(count=pkt[MRI].count, swtraces=pkt[MRI].swtraces)
    ack.show2()
    sendp(ack, iface=iface, verbose=False)
    print ("ACK sent")    

def handle_pkt(pkt):
    print "got a packet"
    pkt.show2()
    sys.stdout.flush()
    send_ack(pkt)

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

class SourceRoutingTail(Packet):
   fields_desc = [ XShortField("etherType", 0x800)]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)
bind_layers(UDP, MRI)
bind_layers(TCP, MRI)

def main():
    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="tcp and port 4321", iface = iface,
          prn = lambda x: handle_pkt(x))
    
if __name__ == '__main__':
    main()

