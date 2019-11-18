#!/usr/bin/env python

from threading import Thread
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
sys.dont_write_bytecode = True

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP, TCP
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
bind_layers(UDP, MRI)

def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Parses command.")
    parser.add_argument("-t", "--topo", type=str, help="Network topology to use.")
    parser.add_argument("-s", "--src", type=str, help="Source host name.")
    parser.add_argument("-d", "--dst", type=str, help="Destination host name.")
    parser.add_argument("-n", "--num", type=int, help="The number of packets to send.")
    options = parser.parse_args(args)
    return options

dict_mri = {}
window = 1


def handle_pkt(ack):
    #print "got ack"
    #ack.show2()
    #sys.stdout.flush()
    global dict_mri
    for i in range(0, len(ack[MRI].swtraces)): 
        dict_mri[ack[MRI].swtraces[i].swid] = ack[MRI].swtraces[i].qdepth
        #if ack[MRI].swtraces[i].qdepth > 1:
        #    window = 1

def send():
    options = getOptions(sys.argv[1:])
    list_switches, dict_host_ip, dict_link_weight, dict_link_port = get_network (options.topo) 
 
    src_host, dst_host = options.src, options.dst
    dst_ip = dict_host_ip[dst_host]
    sp_nodes, sp_ports = get_shorest_path(dict_link_weight, dict_link_port, src = src_host, dst = dst_host)

    iface_tx = get_if()
    global window    
    global dict_mri
    current_time = time.time()
    for i in range(0, int(options.num)):
        if all(value < 5 for value in dict_mri.values()):
             pass
        else:          
            if random.random() < 0.5:
                 sp_nodes, sp_ports = update_shorest_path(dict_mri, dict_link_weight, dict_link_port, src_host, dst_host)
            else:
                window = 1
        print 'Path:', sp_nodes
        j = 0
        pkt = Ether(src=get_if_hwaddr(iface_tx), dst="ff:ff:ff:ff:ff:ff") 
        for p in sp_ports:
            try:
                pkt = pkt / SourceRoute(bos=0, port=p)
                j = j+1
            except ValueError:
                pass
        if pkt.haslayer(SourceRoute):
            pkt.getlayer(SourceRoute, j).bos = 1

        pkt = pkt / IP(dst=dst_ip, proto=17) / UDP(dport=4321, sport=1234) / MRI(count=0, swtraces=[]) / str(RandString(size=1190))
        #pkt.show2()
        #sys.stdout.flush()

        window = window*2
        print window
        sendp(pkt, iface=iface_tx, inter=0, count=window, verbose=False)
        
def receive():    
    iface_rx = 'eth0'
    print "sniffing on %s" % iface_rx
    sys.stdout.flush()
    sniff(filter="udp and port 4322", iface=iface_rx, prn=lambda x: handle_pkt(x))

if __name__ == '__main__':
    Thread(target = send).start()
    Thread(target = receive).start()
