import json

filename = './ring-topo/topology.json'
with open(filename, 'r') as f:
    datastore = json.load(f)
print datastore["hosts"]['h1']['ip']
