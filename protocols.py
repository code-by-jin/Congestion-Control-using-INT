import sys
sys.dont_write_bytecode = True
from scapy.all import *
from scapy.fields import *
from scapy.all import Packet

class SwitchTrace(Packet):
    fields_desc = [ IntField("swid", 0),
                    IntField("qdepth", 0),
                    IntField("egresst", 0),
                    IntField("plength", 0),
                    IntField("txtotal", 0)]
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
