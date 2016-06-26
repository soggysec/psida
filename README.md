PSIDA
=========
### Python Scripts for IDA [[[by the Argus Research Team]]]

PSIDA is a collection of useful Python scripts for IDA.
At this point, PSIDA focuses on collaborative reverse engineering in two models:
 - offline/idb_pickle: you pick up the work at the point your coworker(s) stopped, so you use PSIDA to import the progress made while you were gone
 - online/idb_push: you and your team reverse a binary in parallel and use PSIDA to automatically push notifications about your progress

"Progress" at this point means comments and function names; idb_push sends your updates to everyone working on an IDB with the same name (and connected to the same server, naturally).
 
Internally, idb_pickle is built on IDAPython, while idb_push additionally uses ZeroMQ for communications.


Installation
------------
In order to use PSIDA you need to:
0. Have a 32-bit Python for IDAPython.
1. Copy common.py, idb_pickle.py and idb_push.py into your IDA 6.9/python/ folder.
2. Either copy idapythonrc.py into "%APPDATA%\Hex-Rays\IDA Pro" or (if you already have an idapythonrc.py) add "from PyQt5 import QtGui, QtCore, QtWidgets" to it.
3. If you plan on using idb_push you also need to
	3.1. Install zmq ("pip install pyzmq" does the trick).
	3.2. Install zmq_forwarder as a Windows service and start it (via services.msc); setting it as Automatic is probably a good idea.
	3.3. Change the ZMQ_PUB_CONNECTION_STRING and ZMQ_SUB_CONNECTION_STRING in idb_push.py to use the hostname/IPv4 address of the machine that runs zmq_forwarder (you can also change it at run time).


At this point PSIDA supports only IDA 6.9. It can be made to work on IDA 6.8 (and probably earlier versions), but it's tricky and requires (at least) a recompiled version of the IDAPython plugin.



Usage
------------
idb_pickle: "import idb_pickle" in the Python console, and then "idb_pickle.pickle(<>)" to store your progress to a file and "idb_pickle.unpickle(<>)" to load it.

idb_push: "import idb_push", then ("idb_push.configure(<>)" if you need to, and then) "idb_push.start()"; calling "idb_push.stop()" will close the IDB_PUSH tab.
Inside the IDB_PUSH tab you have several shortcuts:
 - Backspace or Delete discards the selected updates
 - Enter (including the numpad enter) applies the selected updates, as does double clicking an update
 - Space goes to the address of the selected update (only if a single update is selected)



Known Issues
------------
1. Can't connect to the backend server running zmq_forwarder.py: ZMQ currently doesn't support IPv6, and some hostname lookups return IPv6 by default; try to change the hostnames in ZMQ_PUB_CONNECTION_STRING and ZMQ_SUB_CONNECTION_STRING to the IPv4 addresses of the server.

2. IDA freezes occasionally when closing; AFAIK this doesn't have any adverse effect.

3. Occasionally a few of the IDA tabs go black completely (usually the Functions/Names tabs and the main Disassembly tab); pressing Space twice solves it.

4. When you highligh registers an exception is thrown and printed to the console (but has no negative effects otherwise); this has something to do with the default implementation of IDP hooks.


You can always open an issue at https://github.com/argussecurity/psida/issues.


Contributing
------------
Bug fixes and feature pull requests are always welcome, but do review the "Future Plans" and "Known Issues" sections first.



Future Plans
------------
Note: these are not in order of importance!


0. Solve the known issues

1. Write a zmq_forwarder.py alternative for *nix (if we're still using ZeroMQ)
 
2. Merge comments: when you merge you should add the old name (or the alternate name, if unmerged) of the function to the function comments; use repeated comments for this, unless you have regular comments (which override them)

3. Add a Save/Open dialogue for pickle()/unpickle()

4. Implement a runtime progress logger
	- use the hooks in idb_push (factor them out)
	- store all the hooked actions - this gets you all the pickleable changes really fast - which is important since pickle() can be really slow
	- make it run automatically (via idapythonrc.py)
 
5. Add ASLR support - store addresses relative to beginning of segments and offer the user to accept segment rebasing (only if this is actually relevant)

6. Add support for pickling/tracking stack argument names (similar to idc.MakeLocal source code)

7. Add support for pickling/tracking memory address types (word/dword/byte, string, offset, etc.)

8. Add support for pickling/tracking function prototypes (see also "Put on your tinfo_t hat if you're my type" from DefCon 23)
	- idc.GetTinfo(), idc.ApplyType(address, tuple as above)
 
9. Implement a statistics-based stringer - use a large corpus of compiled binaries (with debug data) to deduce what kind of characters, and how much of them, predicts well if this is a string or not

