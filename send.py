#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct

from os import path

import numpy as np
import pandas as pd
from net_topology import get_network, get_shorest_path, update_shorest_path
from protocols import SwitchTrace, MRI, SourceRoute

from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP
from scapy.fields import *

import time

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)
bind_layers(IP, UDP)
bind_layers(UDP, MRI)

def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Parses command.")
    parser.add_argument("-t", "--topo", help="Network topology to use.")
    parser.add_argument("-s", "--src", help="Source host name.")
    parser.add_argument("-d", "--dst", help="Destination host name.")
    parser.add_argument("-n", "--num", type=int, help="The number of packets to send.")
    options = parser.parse_args(args)
    return options

def main():
    options = getOptions(sys.argv[1:])    
    list_switches, dict_host_ip, dict_link_weight, dict_link_port = get_network (options.topo)
    src_host, dst_host = options.src, options.dst
    dst_ip = dict_host_ip[dst_host]   

    addr = socket.gethostbyname(dst_ip)
    iface = get_if()
    
    current_time = time.time()
    sp_nodes, sp_ports = get_shorest_path(dict_link_weight, dict_link_port, src = src_host, dst = dst_host)
    for i in range(0, int(options.num)):
        if time.time() > current_time + 0.5:
            current_time = time.time()
            sp_nodes, sp_ports = update_shorest_path(list_switches, dict_link_weight, dict_link_port, src_host, dst_host, './int_data.pkl')
        print sp_nodes
        j = 0
        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") 
        for p in sp_ports:
            try:
                pkt = pkt / SourceRoute(bos=0, port=p)
                j = j+1
            except ValueError:
                pass
        if pkt.haslayer(SourceRoute):
            pkt.getlayer(SourceRoute, j).bos = 1

        pkt = pkt / IP(dst=addr, proto=17) / UDP(dport=4321, sport=1234) / MRI(count=0, swtraces=[]) / str(RandString(size=10))

        pkt.show2()
        sendp(pkt, iface=iface, inter=0, verbose=False)



if __name__ == '__main__':
    main()

