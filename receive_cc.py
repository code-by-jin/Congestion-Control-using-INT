#!/usr/bin/env python
import os
import sys
import struct
import pandas as pd

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from scapy.fields import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

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

def record_int(pkt):
    print type(pkt.swtraces)
    file_name = "int_data.pkl"    
    df = pd.DataFrame(columns=['0','1','2','3','4','5','6'])
    for i in range(len(pkt.swtraces)):
        swid = str(pkt.swtraces[i].swid)
        df[swid] = [pkt.swtraces[i].qlatency]
    #if os.path.exists("int_data.pkl"):
    #    with open("int_data.pkl", 'rb') as f:
    #        try:
    #            df_exist = pd.read_pickle(file_name)
    #            df = pd.concat([df_exist, df])
    #            df.to_pickle (file_name)
    #        except:
    #            pass
    # else:    
    df.to_pickle (file_name)

count = 0
def handle_pkt(pkt):
    print "got a packet"
    global count
    count += 1
    #record_int(pkt)
    pkt.show2()
    sys.stdout.flush()
    print(count)
    print(pkt.time)

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

class SourceRoutingTail(Packet):
   fields_desc = [ XShortField("etherType", 0x800)]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)
bind_layers(IP, UDP)
bind_layers(UDP, MRI)

def main():
    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
