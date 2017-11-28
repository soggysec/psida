import idaapi
import idc
import ida_kernwin
import socket
from PyQt5 import QtGui, QtCore, QtWidgets


class IdbPushPlugin(idaapi.plugin_t):
    flags = None
    comment = """  Press Ctrl+Shift+P to start the plugin.
                Troubleshooting:
                    - Make sure psida's directory is in your PYTHONPATH
                    - Run `import psida; psida.idb_push.configure(backend_hostname='<your backend server or IP>')`"""
    help = str(comment)
    wanted_name = "psida's IDB Push v0.2"
    wanted_hotkey = "Ctrl-Shift-P"
    imported = False
    running = False
    psida_module = None

    def init(self):
        try:
            import psida
            self.psida_module = psida
            self.imported = True

            if self.psida_module.idb_push.CONFIGURATION["debug"]:
                idaapi.msg("DEBUG - Init - Successfully initialized and imported psida\n")

            return idaapi.PLUGIN_KEEP
        except ImportError:
            psida = None
            self.psida_module = psida
            idaapi.msg("Error importing psida module. Make sure it resides in any directory that is in your PYTHONPATH\n")
            return idaapi.PLUGIN_HIDE

    def reload(self):
        try:
            self.psida_module.idb_push.stop()
            self.running = False
            idaapi.msg("DEBUG - Run - idb_push already running, stopping and reloading...\n")
            reload(self.psida_module)

            if self.psida_module.idb_push.CONFIGURATION["debug"]:
                idaapi.msg("DEBUG - Reload - Successfully reloaded psida\n")

            self.psida_module.idb_push.start()
            self.running = True
            if self.psida_module.idb_push.CONFIGURATION["debug"]:
                idaapi.msg("DEBUG - Run - Successfully started idb_push\n")
        except ImportError:
            idaapi.msg("Error reloading psida module. Make sure it resides in any directory that is in your PYTHONPATH\n")
        
    def run(self, arg):
        if self.imported:
            if not self.psida_module.idb_push.CONFIGURATION["backend_hostname"]:
                connected = False
                while not connected:
                    backend_hostname = ida_kernwin.ask_str("Hostname or IP", 0, "Backend not initialized, input your backend's name or IP:")
                    if not backend_hostname:
                        # User canceled
                        return
                    try:
                        print backend_hostname
                        self.psida_module.zmq_primitives.configure(backend_hostname=backend_hostname)
                        reload(self.psida_module)
                        reload(self.psida_module.zmq_primitives)
                        # test connectivity
                        self.psida_module.zmq_primitives.zmq_test_connectivity()
                        connected = True
                    except self.psida_module.zmq_primitives.ZMQConnectionException:
                        idaapi.msg("ERROR - Run - ZMQ Connectivity failed, make sure your server is set-up correctly.\n")
                    except socket.gaierror:
                        idaapi.msg("ERROR - Run - Could not resolve server name. Make sure it's spelled correctly, and that you get DNS responses from it\n")

            if self.running:
                # Reload only if in debug mode. Do nothing otherwise
                if self.psida_module.idb_push.CONFIGURATION["debug"]:
                    self.reload()
            else:
                reload(self.psida_module)
                self.psida_module.idb_push.start()
                if self.psida_module.idb_push.CONFIGURATION["debug"]:
                    idaapi.msg("DEBUG - Run - Successfully started idb_push\n")
                self.running = True

    def term(self):
        if self.running:
            self.psida_module.idb_push.stop()
            self.running = False
            if self.psida_module.idb_push.CONFIGURATION["debug"]:
                idaapi.msg("DEBUG - Term - Successfully stopped idb_push\n")


def PLUGIN_ENTRY():
    return IdbPushPlugin()
