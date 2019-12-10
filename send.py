#!/usr/bin/env python

import argparse
import sys
import itertools
from threading import Thread

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
np.random.seed(2)  # reproducible

# global variables for window control and traffic engineer
last_t_sent = 0
dict_mri = {}
dict_weight_update = {}
window = 200
sp_ports = [ ]
THREADHOLD = 0.9
total_sent = 200
Flag = 0

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
    parser.add_argument("-t", "--topo", type=str, default="ring", help="Network topology to use.")
    parser.add_argument("-s", "--src", type=str, default="h1", help="Source host name.")
    parser.add_argument("-d", "--dst", type=str, default="h4", help="Destination host name.")
    parser.add_argument("-n", "--num", type=int, default="1000", help="The number of packets to send.")
    options = parser.parse_args(args)
    return options

def handle_pkt(ack):
    global last_t_sent
    global dict_mri
    global dict_weight_update
    if ack[MRI].count < 2:
        return
    print type(ack[MRI].swtraces)
    swtraces = ack[MRI].swtraces
    swtraces.reverse() 
    t_sent = swtraces[0].egresst
    if t_sent == last_t_sent:
        return 

    # measure inflight bytes for each link
    t_rx = time.time()*1000%100000
    print "Receive Time: ", t_rx
    rtt = (t_rx - t_sent)/1000
    print "RTT: ", rtt
    U_max = 0
 
    for i in range(0, ack[MRI].count):
        sw_src = 's'+str(swtraces[i].swid+1)
        if sw_src == 's101':
            sw_src = 'h1'
        print "SW_SRC: ", sw_src
        if i+1 in range(0, len(swtraces)):
            sw_dst = 's'+str(swtraces[i+1].swid+1)
        sw_dst = 'h4'
        link = (sw_src, sw_dst)
        print dict_mri
        q_len = swtraces[i].qdepth   
        if (link in dict_mri) and Flag==1:
            tx_rate = (swtraces[i].txtotal - dict_mri[link].txtotal) / (swtraces[i].egresst - dict_mri[link].egresst)
            U = (q_len + rtt*tx_rate) / 2000000 
        else:
            U = THREADHOLD

        if U == 0:
            U = 0.1
        print U
        if U > U_max:
            U_max = U
        dict_mri[link] = swtraces[i]
        dict_weight_update[link] = U
    print "U_MAX: ", U_max
    send_pkt(U_max)

def send_pkt(U):
    
    global window
    global sp_ports
    global dict_weight_update
    global total_sent
    global Flag
    options = getOptions(sys.argv[1:])
    list_switches, dict_host_ip, dict_link_weight, dict_link_port = get_network (options.topo) 
 
    src_host, dst_host = options.src, options.dst
    dst_ip = dict_host_ip[dst_host]
    sp_nodes, sp_ports = get_shorest_path(dict_link_weight, dict_link_port, src = src_host, dst = dst_host)

    iface_tx = get_if()
    
    if Flag == 0:
        window = window

    elif random.random() < 0.5:
        Flag = 0
        sp_nodes, sp_ports = update_shorest_path(dict_weight_update, dict_link_weight.copy(), dict_link_port, src_host, dst_host)
    else:
        Flag = 1
        window = int(window/(U/THREADHOLD)) + 10

    print 'Path:', sp_ports
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
    t = time.time()*1000%100000
    pkt = pkt / IP(dst=dst_ip, proto=17) / UDP(dport=4321, sport=1234) / MRI(count=1, swtraces=[SwitchTrace(swid=100, egresst=t)]) / str(RandString(size=1000))  
        
    if window + total_sent > int(options.num):
        window = int(options.num) - total_sent
        sendp(pkt, iface=iface_tx, inter=0, count=window, verbose=False)
        exit()
    total_sent = total_sent + window
    print ("Window is: ", window)
    print ("Route is: ", sp_ports)        
    print ("Total Sent: ", total_sent)
    sendp(pkt, iface=iface_tx, inter=0, count=window, verbose=False)

def warm_up():
    options = getOptions(sys.argv[1:])
    list_switches, dict_host_ip, dict_link_weight, dict_link_port = get_network (options.topo)

    src_host, dst_host = options.src, options.dst
    dst_ip = dict_host_ip[dst_host]
    sp_nodes, sp_ports = get_shorest_path(dict_link_weight, dict_link_port, src = src_host, dst = dst_host)
   
    global window
    
    iface_tx = get_if()
    
    print 'Path:', sp_ports
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
    print ("Winodow is: ", window)
    print ("Route is: ", sp_ports)
    t = time.time()*1000%100000
    print "Send Time: ", t
    pkt = pkt / IP(dst=dst_ip, proto=17) / UDP(dport=4321, sport=1234) / MRI(count=1, swtraces=[SwitchTrace(swid=100, egresst=t)]) / str(RandString(size=1000)) 
    sendp(pkt, iface=iface_tx, inter=0, count=window, verbose=False)  
         
def main():    
    iface_rx = 'eth0'
    print "sniffing on %s" % iface_rx
    sys.stdout.flush()
    sniff(filter="udp and port 4322", iface=iface_rx, prn=lambda x: handle_pkt(x))
 
if __name__ == '__main__':
    Thread(target = warm_up).start()
    Thread(target = main).start()

