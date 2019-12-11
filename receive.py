#!/usr/bin/env python
import os
import sys
import struct
import pandas as pd
import argparse

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

dict_mri = {}

def send_ack(pkt):
    iface = get_if()

    options = getOptions(sys.argv[1:])
    list_switches, dict_host_ip, dict_link_weight, dict_link_port = get_network (options.topo) 
    global dict_mri

    flag = 0    
    for i in range(0, len(pkt[MRI].swtraces)): 
        dict_mri[pkt[MRI].swtraces[i].swid] = pkt[MRI].swtraces[i].qdepth
        if pkt[MRI].swtraces[i].qdepth > 5:
            flag = 1

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    
    src_host = dict_host_ip.keys()[dict_host_ip.values().index(src_ip)]
    dst_host = dict_host_ip.keys()[dict_host_ip.values().index(dst_ip)]

    sp_nodes, sp_ports = update_shorest_path(dict_mri, dict_link_weight, dict_link_port, src=dst_host, dst=src_host)

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

count = 0

def handle_pkt(pkt):
    global count
    count = count + 1
    print "in total number: ", count
    pkt.show2()
    sys.stdout.flush()
    send_ack(pkt)

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)
bind_layers(UDP, MRI)

def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Parses command.")
    parser.add_argument("-t", "--topo", type=str, default="ring", help="Network topology to use.")
    options = parser.parse_args(args)
    return options

def main():
    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface = iface,
          prn = lambda x: handle_pkt(x))
    
if __name__ == '__main__':
    main()

