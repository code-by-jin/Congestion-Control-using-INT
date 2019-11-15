# Route-Planning-with-INT
Based on the INT information, redirect the paths for the source routing.

# Requirement
The program can be executed in the same path as https://github.com/p4lang/tutorials/tree/master/exercises/source\_routing. 

1.After compiling p4 file, in another terminal, run ```cd topology```.

2.Choose the topology (ring or spine) you want to use, then run ```python ./ring/controller.py```;

3.In the Mininet CLI ```mininet>```, run ```xterm h1 h4``` to open terminals for h1, h4 respectively.

4.In h4's terminial, run ```python receive.py``` 

5.In h1's terminial, ```python send.py -t ring -s h1 -d h4 -n 100```. to send 100 packets from h1 to h4. Note: run ```python send.py -h```



