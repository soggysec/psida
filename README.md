PSIDA
=========
### Python Scripts for IDA [by the Argus Research Team]

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

1. Copy idb_push_common.py, idb_pickle.py and idb_push.py into your IDA 6.9/python/ folder.

2. Either copy idapythonrc.py into "%APPDATA%\Hex-Rays\IDA Pro" or (if you already have an idapythonrc.py) add "from PyQt5 import QtGui, QtCore, QtWidgets" to it.

3. To use idb_push you also need to:

    3.1. Create a back-end server with:

        3.1.1. zmq ("pip install pyzmq" should do the trick).

	    3.1.2. zmq_forwarder as a Windows service; starting it (via services.msc) and setting it as Automatic is probably a good idea.

	3.2. And on every local host - Set the back-end host name via idb_push.configure(backend_hostname='your_backend_hostname_or_ip'); this setting is permanently saved in idb_push.cfg.


At this point PSIDA supports only IDA 6.9. It can be made to work on IDA 6.8 (and probably earlier versions), but it's tricky and requires (at least) a recompiled version of the IDAPython plugin that exposes the necessary functions.



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
1. Can't connect to the backend server running zmq_forwarder.py: ZMQ currently doesn't support IPv6, and some hostname lookups return IPv6 by default; to work around the issue set the back-end hostname to the IPv4 addresses of the server via idb_push.configure(backend_hostname='<your backend IP>').

2. IDA freezes occasionally when closing; AFAIK this doesn't have any adverse effect.

3. Occasionally a few of the IDA tabs go black completely (usually the Functions/Names tabs and the main Disassembly tab); pressing Space twice solves it.


You can always open an issue at https://bitbucket.org/argussecurity/psida/issues.


Contributing
------------
Bug fixes and feature pull requests are always welcome!
