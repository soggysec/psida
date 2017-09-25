import pprint

import idaapi
from PyQt5 import QtCore

import psida_common
import zmq_primitives
import hooks
import idb_push_ui
import idb_push_ops

from idb_push_config import *
CONFIGURATION = get_configuration()

# Reload hack for debug sessions
if CONFIGURATION[DEBUG]:
    reload(psida_common)
    reload(zmq_primitives)
    reload(hooks)
    reload(idb_push_ui)
    reload(idb_push_ops)

# Global for holding IDB hooks currently registered
g_idb_hook = hooks.IDBHook()

# Holds the current thread running for receiving incoming updates
g_receive_thread = None
# Holds the current instance of the UI form
g_form = None


class ReceiveThread(QtCore.QThread):
    """
    This thread runs at the beginning and listens for incoming updates, then updates the form accordingly
    """
    def __init__(self):
        super(ReceiveThread, self).__init__()
        self._should_stop = False
        self._socket = zmq_primitives.zmq_open_sub_socket()  # cause default arguments

    def signal_stop(self):
        self._should_stop = True

    def run(self):
        while True:
            if self._should_stop:
                return
            try:
                _, json_message = self._socket.recv_multipart()
                update = idb_push_ops.from_json(json_message)
                if update is None:
                    continue

                if CONFIGURATION['debug']:
                    print 'DEBUG - ReceiveThread - Received message %s' % pprint.pformat(update.to_dict())

                idb_push_ui.update_form(update)

            except zmq_primitives.zmq.error.Again:
                # timeout - that's OK
                continue
            except zmq_primitives.zmq.ZMQBaseError:
                # anything else - close and reopen the socket
                traceback.print_exc()
                self._socket.close()

                self._socket = zmq_primitives.zmq_open_sub_socket()  # cause default arguments


def start():
    """
    Boots idb_push by:
        - Testing connectivity to the server
        - Opening the global socket
        - Hooks the relevant IDB events
        - Hooks the UI context-menu element
        - Installs a call to 'stop' when ida closes
    """
    print 'INFO - Configuration - \r\n' + pprint.pformat(CONFIGURATION)

    # test connectivity
    zmq_primitives.zmq_test_connectivity()
    # open global socket
    hooks.g_zmq_socket = zmq_primitives.zmq_open_pub_socket()  # default arguments

    if not g_idb_hook.hook():
        raise Exception('IDBHook installation FAILED')

    hooks.g_hooks_enabled = True

    global g_receive_thread
    g_receive_thread = ReceiveThread()
    g_receive_thread.start()

    global g_form
    g_form = idb_push_ui.IDBPushForm(_remove_hooks_and_stop_thread)
    g_form.Show('IDB PUSH')

    hooks.install_ui_hooks()

    # register for when IDA terminates
    idaapi.notify_when(idaapi.NW_TERMIDA, stop)


def _remove_hooks_and_stop_thread():
    hooks.g_hooks_enabled = False
    g_idb_hook.unhook()

    global g_receive_thread
    if g_receive_thread is not None:
        g_receive_thread.signal_stop()

    hooks.uninstall_ui_hooks()


def restart():
    stop()
    start()


def stop(reason=None):
    """
    Stops ibd_push by
        - Closing the global socket
        - Removing the relevant IDB events hooks
        - Removing the UI hooks
        - Stopping the receive thread
        - Closes the UI form

    :param reason: The reason for idb_push's stop
    """
    if hooks.g_zmq_socket:
        hooks.g_zmq_socket.close()
    _remove_hooks_and_stop_thread()

    global g_form
    if g_form is not None and reason != idaapi.NW_TERMIDA:
        g_form.Close(idaapi.PluginForm.WOPN_RESTORE)

