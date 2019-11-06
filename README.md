# Route-Planning-with-INT
Based on the INT information, redirect the paths for the source routing.

# Requirement
The program can be executed in the same path as https://github.com/p4lang/tutorials/tree/master/exercises/source_routing. 

1.After compiling p4 file, in another terminal, run ```cd ring-topo``` and then run ```python controller.py```;

2.In the Mininet CLI ```mininet>```, run ```xterm h1 h2 h3 h4``` to open terminals for h1, h2, h3 and h4 respectively.

3.Create Congestion from h2 to h3: In h3's terminial, run ```python receive_cc.py``` and in h2's terminial, ```python send_cc.py 10.0.3.3 h2 h3 100```.

4.Send a flow of 100 packets from h1 to h4: In h4's terminial, run ```python receive.py``` and in h1's terminial, ```python send.py 10.0.4.4 h1 h4 100```.

