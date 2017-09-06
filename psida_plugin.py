import idaapi

class psida_Plugin(idaapi.plugin_t):
    flags = None
    comment = "Some comment"
    help = """  Press Ctrl+Shift+P to start the plugin.
                Troubleshooting:
                    - Make sure psida's directory is in your PYTHONPATH
                    - Run `import psida; psida.configure(backend_hostname='<your backend server or IP>')`"""
    wanted_name = "psIDA v0.2"
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
            idaapi.msg("Error importing psida module. Make sure it resides in any directory that is in your PYTHONPATH\n")
            return idaapi.PLUGIN_HIDE
        
    def run(self, arg):
        if self.imported:
            if not self.psida_module.idb_push.CONFIGURATION["backend_hostname"]:
                idaapi.msg("Backend hostname is not initialied, run `import psida; psida.configure(backend_hostname='<your backend server or IP>')` to configure it\n")
                return
            if self.running:
                self.psida_module.idb_push.stop()
                if self.psida_module.idb_push.CONFIGURATION["debug"]:
                    idaapi.msg("DEBUG - Run - idb_push already running, stopping...\n")
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
    return psida_Plugin()