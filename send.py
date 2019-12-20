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

# global variables and constants for window control and traffic engineer
last_t_sent = 0
lastSwtrace = {}
dict_link_weight = {}
wCurr = 50

WBASE = 50
WADD = 10
WMAX = 200
WMIN = 1
THRESHOLD = 0.7
PROB_CONGESTION = 0.6
PROB_NON_CONGESTION = 0.1
DEFAULT_WEIGHT = 0.01

totalSent = 0
justChangeRoute = 1
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

# Bind layers as new protocols are added
bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)
bind_layers(UDP, MRI)

def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Parses command.")
    parser.add_argument("-t", "--topo", type=str, default="ring", help="Network topology to use.")
    parser.add_argument("-s", "--src", type=str, default="h1", help="Source host name.")
    parser.add_argument("-d", "--dst", type=str, default="h4", help="Destination host name.")
    parser.add_argument("-n", "--num", type=int, default="5000", help="The number of packets to send.")
    options = parser.parse_args(args)
    return options

# Read aruguments the users input and make the network topology information available globally 
options = getOptions(sys.argv[1:]) 
list_switches, dict_host_ip, dict_link_weight, dict_link_port = get_network (options.topo)
src_host, dst_host = options.src, options.dst
dst_ip = dict_host_ip[dst_host]
nCurr, rCurr = get_shorest_path(dict_link_weight, dict_link_port, src = src_host, dst = dst_host)
goalSent = int(options.num)


def measureInflight(ack, rtt):
    U = {}
    swtraces = ack[MRI].swtraces # Read INT information
    swtraces.reverse() # Reverse the swtraces to make it in the order of src to dst

    # Traverse links between switches.
    for i in range(1, ack[MRI].count-1): # Ignore the link between switch and host 
        swSrc = 's'+str(swtraces[i].swid+1)
        swDst = 's'+str(swtraces[i+1].swid+1)
        link = (swSrc, swDst)
        qLen = swtraces[i].qdepth

        txDiff = swtraces[i].txtotal - lastSwtrace[i].txtotal
        timeDiff = swtraces[i].egresst - lastSwtrace[i].egresst
        txRate = float(txDiff)/timeDiff 
        U[link] = (qLen*swtraces[i].plength + rtt*txRate) / (0.5*rtt) # 0.5 megabytes/second = 0.5 bytes/microsecond
    return U    

def congestionControl(U, wCurr):

    uMax = max(U.values())
    if uMax > THRESHOLD:
        w = int(wCurr/(uMax/THRESHOLD)) 
    else:
        w = wCurr + WADD 
    return max(min(w, WMAX), WMIN) # Make sure the window is between WMIN and WMAX

def trafficEngineer(U):
    global dict_link_weight, dict_link_port, src_host, dst_host
    # To avoid changes in the orginal dictionary
    G = dict_link_weight.copy()
   
    for link in U.keys():
        G[link] = max(U[link], DEFAULT_WEIGHT)
    nodes, route = get_shorest_path(G, dict_link_port, src = src_host, dst = dst_host)
    return nodes, route

def react_ack(ack):
    # Filter the packets which are not INT acks from receiver
    if MRI not in ack:
        return
    if ack[MRI].count < 2:
        return


    global last_t_sent, justChangeRoute, wCurr, rCurr, nCurr, lastSwtrace

    # Only react to the first packet sent with a new window
    tTx = ack[MRI].swtraces[-1].egresst
    if tTx > last_t_sent:    
        last_t_sent = tTx
        
        # Check if the route changed.
        if justChangeRoute:
            window = wCurr
            route = rCurr
            nodes = nCurr 
        else:    
            #tRx = (time.time()-time_start)*1000000 # timestamp in the unit of microsecond
            #rtt = (tRx - tTx)
            rtt = 150000.0
            #print "RTT: ", rtt
            U = measureInflight(ack, rtt)
            window = congestionControl(U, wCurr)
            route = rCurr
            nodes = nCurr
            print "U Max: ", max(U.values())
            if max(U.values()) > THRESHOLD:
                if random.random() < PROB_CONGESTION:
                    nodes, route = trafficEngineer(U)
            else:
                if random.random() < PROB_NON_CONGESTION:
                    nodes, route = trafficEngineer({})
        if route != rCurr:
            justChangeRoute = 1
            window = min(WBASE, window)
        else:
            justChangeRoute = 0
    	wCurr = window
    	rCurr = route
        nCurr = nodes
    	print "If Change the Route: ", justChangeRoute
    	send()

    # Remember the current INT information 
    lastSwtrace = ack[MRI].swtraces
    lastSwtrace.reverse() # Reverse the swtraces to make it in the order of src to dst

def send(): 
    iface_tx = get_if()
    global wCurr, rCurr
    j = 0
    pkt = Ether(src=get_if_hwaddr(iface_tx), dst="ff:ff:ff:ff:ff:ff")
    for p in rCurr:
        try:
            pkt = pkt / SourceRoute(bos=0, port=p)
            j = j+1
        except ValueError:
            pass
    if pkt.haslayer(SourceRoute):
        pkt.getlayer(SourceRoute, j).bos = 1
    
    # Check if sent enough packets
    global totalSent

    if wCurr + totalSent >= goalSent:
        wCurr = goalSent - totalSent
        print "Time Start: ", time_start # Recorded for FCT evaluation
    totalSent = totalSent + wCurr
    print ("Winodow is: ", wCurr)
    print ("Route is: ", nCurr)
    t = (time.time()-time_start)*1000000 # timestamp in the unit of microsecond
    pkt = pkt / IP(dst=dst_ip, proto=17) / UDP(dport=4321, sport=1234) / MRI(count=1, swtraces=[SwitchTrace(swid=100, egresst=t)]) / str(RandString(size=1000))
    sendp(pkt, iface=iface_tx, inter=0, count=wCurr, verbose=False)  

def receive():    
    iface_rx = 'eth0'
    print "sniffing on %s" % iface_rx
    sys.stdout.flush()
    sniff(filter="udp and port 4322", iface=iface_rx, prn=lambda x: react_ack(x))

if __name__ == '__main__':
    Thread(target = receive).start()
    Thread(target = send).start()
