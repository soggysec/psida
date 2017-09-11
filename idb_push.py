import pprint

import idc
import idaapi
from PyQt5 import QtCore

import psida_common
import zmq_primitives
import hooks
import idb_push_ui
import idb_push_ops
from idb_push_config import *

if CONFIGURATION[DEBUG]:
    reload(psida_common)
    reload(zmq_primitives)
    reload(hooks)
    reload(idb_push_ui)
    reload(idb_push_ops)

# globals
g_idp_hook = hooks.IDPHook()
g_idb_hook = hooks.IDBHook()

g_receive_thread = None

g_form = None


class ReceiveThread(QtCore.QThread):
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
    print 'INFO - Configuration - \r\n' + pprint.pformat(CONFIGURATION)

    # test connectivity
    zmq_primitives.zmq_test_connectivity()
    # open global socket
    hooks.g_zmq_socket = zmq_primitives.zmq_open_pub_socket()  # default arguments

    if not g_idp_hook.hook():
        raise Exception('IDPHook installation FAILED')

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
    g_idp_hook.unhook()
    g_idb_hook.unhook()

    global g_receive_thread
    if g_receive_thread is not None:
        g_receive_thread.signal_stop()

    hooks.uninstall_ui_hooks()


def restart():
    stop()
    start()


def stop(reason=None):
    hooks.g_zmq_socket.close()
    _remove_hooks_and_stop_thread()

    global g_form
    if g_form is not None and reason != idaapi.NW_TERMIDA:
        g_form.Close(idaapi.PluginForm.FORM_SAVE)

