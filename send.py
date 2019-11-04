#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct

from os import path

import numpy as np
import pylab as plt
import networkx as nx
import pandas as pd

from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP
from scapy.all import IntField, FieldListField, FieldLenField, ShortField, PacketListField
from scapy.layers.inet import _IPOption_HDR
from scapy.fields import *

from time import sleep

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

class SwitchTrace(Packet):
    fields_desc = [ IntField("swid", 0),
                  IntField("qlatency", 0)]
    def extract_padding(self, p):
                return "", p

class MRI(Packet):
   fields_desc = [ ShortField("count", 0),
                   PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1))]

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)
bind_layers(IP, UDP)
bind_layers(UDP, MRI)

def UpdateWeights(dict_weight, int_data):
    # updated network weights with INT info

    df = int_data.iloc[-1]

    swids = ['0', '1', '2', '3', '4', '5', '6']
    sws = ['s1', 's2', 's3', 's4', 's5', 's6', 's7']
    dict_sw = dict(zip(swids, sws))
    for swid in swids:
        if np.isnan(df[swid]):
            continue
        for (key, value) in dict_weight.items():
            if key[0] == dict_sw[swid]:
                dict_weight[key] = df[swid]
    
def ShorestPath(links, src = 'h1', dst = 'h4'):

    edges = [x[:-2] for x in links]
    weights = [x[-2] for x in links]
    ports = [x[-1] for x in links]
    dict_weight = dict(zip(edges, weights))
    dict_port = dict(zip(edges, ports))

    #updated network weights with INT info
    #if os.path.exists("int_data.pkl"):
    #    with open("int_data.pkl", 'rb') as f:
    #        try:
    #            int_data = pd.read_pickle('./int_data.pkl')
    #            UpdateWeights(dict_weight, int_data)
    #        except:
    #            print("Error when reading pkl")
    weighted_edges = [key + (value, ) for (key, value) in dict_weight.items()]  
    print weighted_edges
    # Create Topology with the updated weights
    G=nx.DiGraph()
    G.add_weighted_edges_from(weighted_edges)

    shortes_path_nodes = (nx.dijkstra_path(G=G, source=src, target=dst, weight='weight'))
    shortes_path_ports = [dict_port[(v, w)] for v, w in zip(shortes_path_nodes[:-1], shortes_path_nodes[1:])][1:]
  
    return shortes_path_nodes, shortes_path_ports

def main():

    if len(sys.argv)<3:
        print 'pass 2 arguments: "<message>"'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    # initialize the network [sr_node, dst_node, weight, port]
    links = [('h1','s1', 20, 0), ('s1','h1', 20, 1),
             ('h2','s2', 20, 0), ('s2','h2', 20, 1), 
             ('h3','s3', 20, 0), ('s3','h3', 20, 1),
             ('h4','s4', 20, 0), ('s4','h4', 20, 1), 
             ('s1','s2', 20, 2), ('s2','s1', 20, 3),
             ('s2','s3', 20, 2), ('s3','s2', 20, 3),
             ('s3','s4', 20, 2), ('s4','s3', 20, 3), 
             ('s4','s5', 20, 2), ('s5','s4', 20, 2), 
             ('s5','s6', 20, 1), ('s6','s5', 20, 2),
             ('s6','s7', 20, 1), ('s7','s6', 20, 2),
             ('s7','s1', 20, 1), ('s1','s7', 20, 3)]
    src = sys.argv[2]
    dst = sys.argv[3]
    timeout = time.time() + 10
    send_time = 0
    count_send = 0
    current_time = time.time()
    shortes_path_nodes, shortes_path_ports = ShorestPath(links, src = src, dst = dst)
    for i in range(0, int(sys.argv[5])):
        if time.time > current_time + 0.5:
            current_time = time.time() 
            shortes_path_nodes, shortes_path_ports = ShorestPath(links, src = src, dst = dst)
            print shortes_path_nodes
        j = 0
        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") 
        for p in shortes_path_ports:
            try:
                pkt = pkt / SourceRoute(bos=0, port=p)
                j = j+1
            except ValueError:
                pass
        if pkt.haslayer(SourceRoute):
            pkt.getlayer(SourceRoute, j).bos = 1

        pkt = pkt / IP(dst=addr, proto=17) / UDP(dport=4321, sport=1234) / MRI(count=0, swtraces=[]) / str(RandString(size=10))

        pkt.show2()
        if count_send == 0:
            send_time = pkt.time
        sendp(pkt, iface=iface, inter=0, verbose=False)
        count_send = count_send + 1
    print(count_send)
    print(send_time)    

if __name__ == '__main__':
    main()
