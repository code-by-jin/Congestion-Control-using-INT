import os
import sys
sys.dont_write_bytecode = True

import json
import networkx as nx
import pandas as pd
import numpy as np
DEFAULT_WEIGHT = 0.01
HOST_TO_SWITCH_PORT = 0

def get_network (topo = "ring"):
    
    # Read JSON file which contains corresponding topology information. 
    try:
        file_path = './topology/'+topo+'/topology.json'
        with open(file_path, 'r') as f:
            dict_net = json.load(f)
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
        sys.exit(1)
    except:
        print "Unexpected error:", sys.exc_info()[0]
        sys.exit(1)
    
    dict_switches, dict_hosts, list_links = dict_net['switches'], dict_net['hosts'], dict_net['links']
    
    # From dict_switches, get the list of switches
    list_switches = dict_net['switches'].keys()
    
    # From dict_hosts, get the ip for each host
    dict_host_ip = {}
    for key, value in dict_hosts.items():
        dict_host_ip[key] = value['ip'][:-3]    

    # From dict_links, get the weight and output port for each directed link
    dict_link_weight, dict_link_port = {}, {}

    for link in list_links:
        if link[0][0] == 'h':
            port_src = HOST_TO_SWITCH_PORT
        else:
            port_src = int(link[0][-1])
        
        if link[1][0] == 'h':
            port_dst = HOST_TO_SWITCH_PORT
        else:
            port_dst = int(link[1][-1])
        
        dict_link_weight[(link[0][:2], link[1][:2])] = DEFAULT_WEIGHT
        dict_link_weight[(link[1][:2], link[0][:2])] = DEFAULT_WEIGHT

        dict_link_port[(link[0][:2], link[1][:2])] = port_src
        dict_link_port[(link[1][:2], link[0][:2])] = port_dst 

    return list_switches, dict_host_ip, dict_link_weight, dict_link_port

def update_shorest_path(dict_mri, dict_link_weight, dict_link_port, src = 'h1', dst = 'h4'):
    
    # Update link-wieght dictionary 
    for sw in dict_mri.keys():
        for src_dst in dict_link_weight.keys():
            if src_dst[0] == sw:
                dict_link_weight[src_dst] = dict_mri[sw] + 1
     
    shortes_path_nodes, shortes_path_ports = get_shorest_path (dict_link_weight, dict_link_port, src, dst)
    return shortes_path_nodes, shortes_path_ports

def get_shorest_path (dict_link_weight, dict_link_port, src = 'h1', dst = 'h4'):

    weighted_edges = [key + (value, ) for (key, value) in dict_link_weight.items()]

    # Create Topology with the updated weights
    G=nx.DiGraph()
    G.add_weighted_edges_from(weighted_edges)

    shortes_path_nodes = (nx.dijkstra_path(G=G, source=src, target=dst, weight='weight'))
    shortes_path_ports = [dict_link_port[(v, w)] for v, w in zip(shortes_path_nodes[:-1], shortes_path_nodes[1:])][1:]

    return shortes_path_nodes, shortes_path_ports

