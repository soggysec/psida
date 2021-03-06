PSIDA
=========
### Python Scripts for IDA [Forked from the original version by the Argus Research Team]

PSIDA is a collection of useful Python scripts for IDA.
At this point, PSIDA focuses on collaborative reverse engineering in two models:
 - offline/idb_pickle: you pick up the work at the point your coworker(s) stopped, so you use PSIDA to import the progress made while you were gone
 - online/idb_push: you and your team reverse a binary in parallel and use PSIDA to automatically push notifications about your progress

"Progress" at this point means comments, function names, variable names and address names; idb_push sends your updates to everyone working on an IDB with the same name (and connected to the same server, naturally).
 
Internally, idb_pickle is built on IDAPython, while idb_push additionally uses ZeroMQ for communications.


Installation
------------
In order to use PSIDA you need to:

0. Have a 32-bit Python for IDAPython.

1. Place the psida directory is in your PYTHONPATH

2. Move psida/psida_plugin.py to: IDA 7.0/plugins/ 

3. To use the online feature you also need to:

    2.1. Create a back-end server and:

       - Install zmq (`pip install pyzmq` should do the trick).

       - Run zmq_forwarder on your network, accessible from all clients

    2.2. On every local host:

       - Install zmq (`pip install pyzmq` should do the trick).


This version of PSIDA focuses on IDA 7.0. 



Usage
------------
idb_pickle (offline): 

Creating a pickle file:
 > from psida import idb_pickle
 > idb_pickle.pickle('/tmp/output.pickle') #Optionally, you can call (un)pickle without any parameters and it will prompt you for a location

Unpickling on a different IDB:
 > from psida import idb_pickle
 > idb_pickle.unpickle('/tmp/output.pickle')

idb_push (online): 
 - You will first need to make sure that pyzmq has been installed and that zmq_forwarder.py is running:
 $> pip install pyzmq
 $> python zmq_forwarder.py

 In IDA:
 - Press Ctrl+Shift+P. The IDB_PUSH window will appear. (At the first run, you will be asked to input your backend hostname or IP address)
 - NOTE: IPv6 will likely not work

Inside the IDB_PUSH tab you have several shortcuts:

 - Backspace or Delete discards the selected updates

 - Enter (including the numpad enter) applies the selected updates, as does double clicking an update

 - Space goes to the address of the selected update (only if a single update is selected)



Known Issues
------------
1. Can't connect to the backend server running zmq_forwarder.py: ZMQ currently doesn't support IPv6, and some hostname lookups return IPv6 by default; to work around the issue set the back-end hostname to the IPv4 addresses of the server via psida.idb_push.configure(backend_hostname='<your backend IP>').

2. IDA freezes occasionally when closing; AFAIK this doesn't have any adverse effect.

3. Occasionally a few of the IDA tabs go black completely (usually the Functions/Names tabs and the main Disassembly tab); pressing Space twice solves it.

4. Renaming addresses that happen to have the same value as some struct's or stack variable's member id won't be transmitted. (Affects addresses that start with 0xFF00XXXX)

5. Changing empty lines in anterior/posterior comments has funky behavior.

6. Changing or creating stack variables' names will not deal correctly with the size of said varaibles. This is expected to be fixed once make data ('d') feature will be added.

7. Removing comments won't be transmitted.

8. Clients not running idb_push when changes are made will not get the updates made by other clients. (There's no persistent storage of changes)

Feel free to submit issues: https://github.com/soggysec/psida/issues

Original Version of PSIDA: https://bitbucket.org/argussecurity/psida


Contributing
------------
Bug fixes and feature pull requests are always welcome!
