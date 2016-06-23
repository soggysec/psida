idb_pickle.py has only one prerequisites, see step (3) below.

idb_push.py has some prerequisites:
1) Run "pip install pyzmq" in a 32-bit Python (if you only have 64-bit Python outside of IDA this WON'T WORK).
2) Copy common.py, idb_pickle.py and idb_push.py from the base directory to your IDA Pro/python folder.
3) Merge C_Users_USER_AppData_Roaming_Hex-Rays_IDA Pro/idapythonrc.py with your idapythonrc.py file in C:\Users\<USER>\AppData\Roaming\Hex-Rays\IDA Pro - if you don't have it use the one in the folder, otherwise add the "from PyQt5 import QtGui, QtCore, QtWidgets" line to your idapythonrc.py file.
4) If you have a hard time connecting to the server you may be using DNSv6 - and ZeroMQ doesn't support it; adding argusbuild to the hosts file (or replacing "argusbuild" with the IP in idb_push.py) should solve it

How to use idb_push.py:
 - in IDA's Python console execute "import idb_push" and then "idb_push.start()"
	- before calling start() you may wanna call idb_push.configure()
	- you can "idb_push.stop()" to remove hooks and stop the receiving thread
 - the IDB_PUSH form displays updates done by other users on the same server (currently argusbuild) working on the same project
	- your default user name is your machine name
	- your project name is the file name of the IDB
 - keyboard shortcuts:
	- Backspace or Delete discards the selected updates
	- Enter (including the numpad enter) applies the selected updates
		- double clicking an update also applies it
	- Space goes to the address of the selected update (only if a single update is selected)

Known issues in idb_push:
1) IDA would freeze occasionally when closing; AFAICT this doesn't corrupt the IDB
2) occasionally a few of the IDA tabs go black completely (this happens rarely and usually affects the Functions/Names tabs and the main Disassembly tab); pressing Space twice solves it
3) [6.9] when you highligh registers an exception is thrown and printed to the console (but has no negative effects otherwise); this has something to do with the default implementation of IDP hooks