# Congestion-Control-with-INT
Based on the INT information, combine traffic engineer and congestion control.

# Requirement
The program can be executed in the same path as https://github.com/p4lang/tutorials/tree/master/exercises/source_routing. 

1.Choose the topology you want to use, the default is ring topology. If you want to use fat tree topology, edit Makefile and change the second line to ```TOPO = topology/spine/topology.json```.

2.Run ```make``` to compile .p4 file.

3.After compiling p4 file, in another terminal, run ```cd topology``` and run ```python ./ring/controller.py``` (run ```python ./spine/controller.py``` if you're using fat tree topology);

4.In the Mininet CLI ```mininet>```, run ```xterm h1 h4``` to open terminals for h1, h4 respectively. 

5.Optional step: run ```xterm h2 h3```, run ```iperf -s -u``` in h3's terminal, run ```iperf -c 10.0.3.3 -u -t 100 -b 4m ``` in h2's terminal to create congestion. 

6.In h4's terminial, run ```python receive.py``` 

7.In h1's terminial, ```python send.py```. to send 10000 packets from h1 to h4. Note: run ```python send.py -h``` to see the options for send.py.




