#!/usr/bin/env python

import argparse
import sys
import itertools
from threading import Thread

import socket
import random
import struct
import copy
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
dict_link_weight = {}
window = 50
sp_ports = []
THREADHOLD = 0.8
total_sent = 50
Flag = 0
time_start = time.time()

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
    parser.add_argument("-n", "--num", type=int, default="10000", help="The number of packets to send.")
    options = parser.parse_args(args)
    return options

def handle_pkt(ack):

    global list_switches, dict_host_ip, dict_link_weight, dict_link_port, src_host, dst_host, dst_ip
    
    local_dict_link_weight = copy.deepcopy(dict_link_weight)
    global last_t_sent
    global dict_mri
    global time_start
    if ack[MRI].count < 2:
        return

    swtraces = ack[MRI].swtraces
    swtraces.reverse() 
    t_sent = swtraces[0].egresst
    if t_sent <= last_t_sent:
        return 
    last_t_sent = t_sent

    # measure inflight bytes for each link
    t_rx = (time.time()-time_start)*1000
    print "Receive Time: ", t_rx
    rtt = (t_rx - t_sent)*1000
    print "RTT: ", rtt
    U_max = 0
 
    for i in range(1, ack[MRI].count-1):
        sw_src = 's'+str(swtraces[i].swid+1)
        if sw_src == 's101':
            sw_src = 'h1'

        if i+1 in range(0, len(swtraces)):
            sw_dst = 's'+str(swtraces[i+1].swid+1)
        else:
            sw_dst = 'h4'
        link = (sw_src, sw_dst)
        print "Link:", link 
        q_len = swtraces[i].qdepth   
        if link in dict_mri:
            tx_diff = swtraces[i].txtotal - dict_mri[link].txtotal
            time_diff = swtraces[i].egresst - dict_mri[link].egresst
            tx_rate = float(tx_diff)/time_diff
            U = (q_len + rtt*tx_rate) / 500000
            print "U: ", U 
        else:
            U = THREADHOLD
        if U < 0.1:
            U = 0.1

        if U > U_max:
            U_max = U
        dict_mri[link] = swtraces[i]
        local_dict_link_weight[link] = U
    print "U_MAX: ", U_max
    send_pkt(U_max, local_dict_link_weight)

def send_pkt(U, local_dict_link_weight):
    
    global list_switches, dict_host_ip, dict_link_weight, dict_link_port, src_host, dst_host, dst_ip
    global sp_nodes, sp_ports
    global total_sent, window
    global time_start
    iface_tx = get_if()
    if U > THREADHOLD:
        window = int(window/(U/THREADHOLD)) + 5
        if random.random() <= 0.5:
            sp_nodes, sp_ports = get_shorest_path(local_dict_link_weight, dict_link_port, src = src_host, dst = dst_host)
    else:
        if random.random() <= 0.1:
            sp_nodes, sp_ports = get_shorest_path(dict_link_weight, dict_link_port, src = src_host, dst = dst_host)
        window = window+5

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
    t = (time.time()-time_start)*1000
    pkt = pkt / IP(dst=dst_ip, proto=17) / UDP(dport=4321, sport=1234) / MRI(count=1, swtraces=[SwitchTrace(swid=100, egresst=t)]) / str(RandString(size=1000))  
        
    if window + total_sent > int(options.num):
        window = int(options.num) - total_sent
    total_sent = total_sent + window
    print ("Window is: ", window)
    print ("Route is: ", sp_ports)        
    print ("Total Sent: ", total_sent)
    sendp(pkt, iface=iface_tx, inter=0, count=window, verbose=False)
    if total_sent == int(options.num):
        print "Time Start: ", time_start
        exit()

def send():
    global time_start
    global options
    options = getOptions(sys.argv[1:])

    global list_switches, dict_host_ip, dict_link_weight, dict_link_port, src_host, dst_host, dst_ip
    list_switches, dict_host_ip, dict_link_weight, dict_link_port = get_network (options.topo)
    src_host, dst_host = options.src, options.dst
    dst_ip = dict_host_ip[dst_host]

    global sp_ports, window
    sp_nodes, sp_ports = get_shorest_path(dict_link_weight, dict_link_port, src = src_host, dst = dst_host)
    
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
    t = (time.time()-time_start)*1000
    print "Send Time: ", t
    pkt = pkt / IP(dst=dst_ip, proto=17) / UDP(dport=4321, sport=1234) / MRI(count=1, swtraces=[SwitchTrace(swid=100, egresst=t)]) / str(RandString(size=1000)) 
    sendp(pkt, iface=iface_tx, inter=0, count=window, verbose=False)  

     
def receive():    
    iface_rx = 'eth0'
    print "sniffing on %s" % iface_rx
    sys.stdout.flush()
    sniff(filter="udp and port 4322", iface=iface_rx, prn=lambda x: handle_pkt(x))

if __name__ == '__main__':
    
    Thread(target = send).start()
    Thread(target = receive).start()

