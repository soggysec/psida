import os
import idaapi
import common
import zmq
import traceback
import json
import time
from idaapi import PluginForm
import idc
import random

from PyQt5 import QtGui, QtCore, QtWidgets


CONTEXT_MENU_ACTION_NAME = "idb_push:send_address"

ZMQ_PUB_CONNECTION_STRING = r"tcp://argusbuild:5559"
ZMQ_SUB_CONNECTION_STRING = r"tcp://argusbuild:5560"

ZMQ_TIMEOUT_MS = 100
ZMQ_CONNECTIVITY_TEST_TIMEOUT = 1000

MAX_ITEMS_IN_LIST = 100

USER = os.getenv('COMPUTERNAME')


class UpdateTypes(object):
    Name, Comment, RepeatableComment, AnteriorLine, PosteriorLine, LookHere = range(6)


def configure(pub_connection_string=None,
              sub_connection_string=None,
              timeout=None,
              max_items=None,
              user=None):
    if pub_connection_string is not None:
        global ZMQ_PUB_CONNECTION_STRING
        ZMQ_PUB_CONNECTION_STRING = pub_connection_string

    if sub_connection_string is not None:
        global ZMQ_SUB_CONNECTION_STRING
        ZMQ_SUB_CONNECTION_STRING = sub_connection_string

    if timeout is not None:
        global ZMQ_TIMEOUT_MS
        ZMQ_TIMEOUT_MS = timeout

    if max_items is not None:
        global MAX_ITEMS_IN_LIST
        MAX_ITEMS_IN_LIST = max_items

    if user is not None:
        global USER
        USER = user


def zmq_test_connectivity(pub_connection_string, sub_connection_string):
    context = zmq.Context()
    random.seed()

    # open a transmitting socket
    tx_socket = context.socket(zmq.PUB)
    tx_socket.setsockopt(zmq.LINGER, ZMQ_TIMEOUT_MS)
    tx_socket.connect(pub_connection_string)
    topic = "0"  # dummy

    # open a receiving socket
    rx_socket = context.socket(zmq.SUB)
    rx_socket.connect(sub_connection_string)
    rx_socket.setsockopt(zmq.SUBSCRIBE, "")
    rx_socket.RCVTIMEO = ZMQ_TIMEOUT_MS

    # sleep to allow both sockets to connect
    time.sleep(ZMQ_TIMEOUT_MS / 1000.0)

    # send a random test packet
    random_string = "%010x" % random.randrange(16 ** 10)
    tx_socket.send_multipart([topic, json.dumps(random_string)])

    # wait for a while for the reply to arrive
    rx_end_time = time.time() + (ZMQ_CONNECTIVITY_TEST_TIMEOUT / 1000.0)
    found_random_string = False

    while time.time() < rx_end_time:
        try:
            _, message = rx_socket.recv_multipart()
            if random_string in message:
                found_random_string = True
                break

        except zmq.error.Again:
            # timeout - that's OK
            continue

    tx_socket.close()
    rx_socket.close()

    if not found_random_string:
        raise Exception("ZMQ connectivity test failed!")


def zmq_pub_json(connection_string, json_message):
    try:
        if 'user' not in json_message:
            json_message['user'] = USER
        if 'project' not in json_message:
            json_message['project'] = os.path.basename(idc.GetIdbPath())

        context = zmq.Context()
        zmq_socket = context.socket(zmq.PUB)
        zmq_socket.setsockopt(zmq.LINGER, ZMQ_TIMEOUT_MS)
        zmq_socket.connect(connection_string)
        topic = "0"  # dummy
        time.sleep(ZMQ_TIMEOUT_MS / 1000.0)
        zmq_socket.send_multipart([topic, json.dumps(json_message)])
        zmq_socket.close()
    except zmq.ZMQBaseError:
        traceback.print_exc()


class RenameIDPHook(idaapi.IDP_Hooks):
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def renamed(self, ea, new_name, local_name):
        # event = "RenameIDPHook.renamed(ea = 0x%x, new_name = %s, local_name = %r)\n" % (ea, new_name, local_name)
        # print event
        if (g_hooks_enabled and
                (new_name is not None) and
                (len(new_name) > 0) and
                (not common.is_default_name(new_name))):
            zmq_pub_json(ZMQ_PUB_CONNECTION_STRING, {'type': UpdateTypes.Name,
                                                     'address': ea,
                                                     'name': new_name})

        return idaapi.IDP_Hooks.renamed(self, ea, new_name, local_name)


class CommentIDBHook(idaapi.IDB_Hooks):
    def __init__(self):
        idaapi.IDB_Hooks.__init__(self)

    def cmt_changed(self, ea, is_repeatable):
        # event = "CommentIDBHook.cmt_changed(arg0 = 0x%x, is_repeatable = %s)" % (ea, is_repeatable)
        # print event

        message = {'address': ea}

        if is_repeatable:
            message['type'] = UpdateTypes.RepeatableComment
            message['comment'] = common.get_repeated_comment(ea)
        else:
            message['type'] = UpdateTypes.Comment
            message['comment'] = common.get_comment(ea)

        if g_hooks_enabled and (message['comment'] is not None) and (len(message['comment']) > 0):
            zmq_pub_json(ZMQ_PUB_CONNECTION_STRING, message)

        return idaapi.IDB_Hooks.cmt_changed(self, ea, is_repeatable)

    def area_cmt_changed(self, areas, area, comment, is_repeatable):
        # event = "CommentIDBHook.area_cmt_changed(area_start = 0x%x, comment = %s)" % (area.startEA, comment)
        # print event

        ea = area.startEA
        message = {'address': ea}

        if is_repeatable:
            message['type'] = UpdateTypes.RepeatableComment
            message['comment'] = common.get_repeated_comment(ea)
        else:
            message['type'] = UpdateTypes.Comment
            message['comment'] = common.get_comment(ea)

        if g_hooks_enabled and (message['comment'] is not None) and (len(message['comment']) > 0):
            zmq_pub_json(ZMQ_PUB_CONNECTION_STRING, message)

        return idaapi.IDB_Hooks.area_cmt_changed(self, areas, area, comment, is_repeatable)

    def extra_cmt_changed(self, ea, line_idx, cmt):
        # event = "CommentIDBHook.extra_cmt_changed(ea = 0x%x, line_idx = %d, cmt = %s)" % (ea, line_idx, cmt)
        # print event

        message = {'address': ea, 'line': cmt}

        if idaapi.E_PREV <= line_idx < idaapi.E_NEXT:
            message['type'] = UpdateTypes.AnteriorLine
            message['line_index'] = line_idx - idaapi.E_PREV
        elif line_idx >= idaapi.E_NEXT:
            message['type'] = UpdateTypes.PosteriorLine
            message['line_index'] = line_idx - idaapi.E_NEXT
        else:
            print "WHAAAAAAT is the meaning of comment |%s| at address 0x%x at index %d?" % (cmt, ea, line_idx)
            return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)

        if g_hooks_enabled and (message['line'] is not None) and (len(message['line']) > 0):
            zmq_pub_json(ZMQ_PUB_CONNECTION_STRING, message)

        return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)


# globals
g_rename_hook = RenameIDPHook()
g_comment_hook = CommentIDBHook()
g_ui_hooks = None
g_hooks_enabled = False
g_receive_thread = None
g_item_list_mutex = None
g_item_list_model = None
g_item_list = None
g_form = None


class ReceiveThread(QtCore.QThread):
    def __init__(self, connection_string):
        super(ReceiveThread, self).__init__()
        self._should_stop = False
        self._connection_string = connection_string
        self._context = zmq.Context()

        self._socket = self._context.socket(zmq.SUB)
        self._socket.connect(connection_string)
        self._socket.setsockopt(zmq.SUBSCRIBE, "")
        self._socket.RCVTIMEO = ZMQ_TIMEOUT_MS

    def signal_stop(self):
        self._should_stop = True

    def run(self):
        while True:
            if self._should_stop:
                # print "Receive thread stopped"
                return
            try:
                _, json_message = self._socket.recv_multipart()
                message = json.loads(json_message)
                if message is None or len(message) == 0:
                    continue
                if 'user' not in message or message['user'] == USER:
                    # don't receive your own updates
                    continue
                if ('project' not in message or
                        message['project'] != os.path.basename(idc.GetIdbPath())):
                    # don't receive updates for other projects
                    continue
                update_form(message)

            except zmq.error.Again:
                # timeout - that's OK
                continue
            except zmq.ZMQBaseError:
                # anything else - close and reopen the socket
                traceback.print_exc()
                self._socket.close()

                self._socket = self._context.socket(zmq.SUB)
                self._socket.connect(self._connection_string)
                self._socket.setsockopt(zmq.SUBSCRIBE, "")
                self._socket.RCVTIMEO = ZMQ_TIMEOUT_MS


def start():
    # test connectivity
    zmq_test_connectivity(ZMQ_PUB_CONNECTION_STRING, ZMQ_SUB_CONNECTION_STRING)

    if not g_rename_hook.hook():
        raise Exception("RenameIDPHook installation FAILED")

    if not g_comment_hook.hook():
        raise Exception("CommentIDBHook installation FAILED")

    global g_hooks_enabled
    g_hooks_enabled = True

    global g_receive_thread
    g_receive_thread = ReceiveThread(ZMQ_SUB_CONNECTION_STRING)
    g_receive_thread.start()

    global g_form
    g_form = IDBPushForm()
    g_form.Show("IDB PUSH")

    install_ui_hooks()

    # register for when IDA terminates
    idaapi.notify_when(idaapi.NW_TERMIDA, stop)


def _remove_hooks_and_stop_thread():
    global g_hooks_enabled
    g_hooks_enabled = False
    g_rename_hook.unhook()
    g_comment_hook.unhook()

    global g_receive_thread
    if g_receive_thread is not None:
        g_receive_thread.signal_stop()

    uninstall_ui_hooks()


def stop(reason=None):
    _remove_hooks_and_stop_thread()

    global g_form
    if g_form is not None and reason != idaapi.NW_TERMIDA:
        g_form.Close(idaapi.PluginForm.FORM_SAVE)


class IDBPushForm(PluginForm):
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.escape_eater = EscapeEater()
        self.parent.installEventFilter(self.escape_eater)

        global g_item_list
        g_item_list = self.items_list = QtWidgets.QListView()

        self.key_press_filter = KeyPressFilter()
        self.items_list.installEventFilter(self.key_press_filter)

        self.items_list.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.items_list.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.items_list.doubleClicked.connect(on_item_list_double_clicked)
        self.items_list.setContextMenuPolicy(QtCore.Qt.ActionsContextMenu)

        apply_action = QtWidgets.QAction('Apply', self.items_list)
        apply_action.triggered.connect(on_apply_button_clicked)
        self.items_list.addAction(apply_action)

        # add another action
        discard_action = QtWidgets.QAction('Discard', self.items_list)
        discard_action.triggered.connect(on_discard_button_clicked)
        self.items_list.addAction(discard_action)

        go_to_address_action = QtWidgets.QAction('Go to address', self.items_list)
        go_to_address_action.triggered.connect(on_go_to_address_button_clicked)
        self.items_list.addAction(go_to_address_action)

        global g_item_list_model
        g_item_list_model = self.model = QtGui.QStandardItemModel(self.items_list)

        global g_item_list_mutex
        g_item_list_mutex = QtCore.QMutex(QtCore.QMutex.Recursive)

        self.PopulateForm()

    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        layout.addWidget(self.items_list)
        self.items_list.setModel(self.model)

        apply_discard_buttons_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(apply_discard_buttons_layout)

        apply_button = QtWidgets.QPushButton('Apply')
        apply_button.clicked.connect(on_apply_button_clicked)
        apply_discard_buttons_layout.addWidget(apply_button)

        ignore_button = QtWidgets.QPushButton('Discard')
        ignore_button.clicked.connect(on_discard_button_clicked)
        apply_discard_buttons_layout.addWidget(ignore_button)

        go_to_address_button = QtWidgets.QPushButton('Go to address')
        go_to_address_button.clicked.connect(on_go_to_address_button_clicked)
        layout.addWidget(go_to_address_button)

        self.parent.setLayout(layout)

    def OnClose(self, form):
        _remove_hooks_and_stop_thread()


def on_go_to_address_button_clicked():
    try:
        g_item_list_mutex.lock()

        indices = g_item_list.selectedIndexes()
        if len(indices) != 1:
            return

        index = indices[0].row()
        address = g_item_list_model.item(index).data()['address']
        idc.Jump(address)

    finally:
        g_item_list_mutex.unlock()


def on_apply_button_clicked():
    try:
        g_item_list_mutex.lock()
        indices = [index.row() for index in g_item_list.selectedIndexes()]

        removed_rows = 0
        # since every time you apply an update you discard it
        # AND you have to keep the update order you need to
        # track the offset for all indices after the one you just removed
        for i in sorted(indices):
            row_was_removed = apply_update(i - removed_rows)
            if row_was_removed:
                removed_rows += 1

        idc.Refresh()

    finally:
        g_item_list_mutex.unlock()


def on_discard_button_clicked():
    try:
        g_item_list_mutex.lock()

        indices = [index.row() for index in g_item_list.selectedIndexes()]
        for i in sorted(indices, reverse=True):
            g_item_list_model.removeRow(i)

    finally:
        g_item_list_mutex.unlock()


def apply_update(row_index):
    """
    Returns True iff row was removed after applying.
    """
    global g_hooks_enabled
    should_remove_row = True

    try:
        g_item_list_mutex.lock()
        g_hooks_enabled = False
        # apply update
        update = g_item_list_model.item(row_index).data()
        update_type = update['type']

        if update_type == UpdateTypes.Name:
            address = update['address']
            name = update['name']
            idc.MakeName(address, str(name))

        elif update_type == UpdateTypes.Comment:
            address = update['address']
            comment = update['comment']
            common.set_comment(address, str(comment))

        elif update_type == UpdateTypes.RepeatableComment:
            address = update['address']
            comment = update['comment']
            common.set_repeated_comment(address, str(comment))

        elif update_type == UpdateTypes.AnteriorLine:
            address = update['address']
            line_index = update['line_index']

            # in order for line i to be displayed all lines before i
            # must be non-empty
            for i in xrange(0, line_index):
                line = idc.LineA(address, i)
                if line is None or len(line) == 0:
                    idc.ExtLinA(address, i, " ")

            idc.ExtLinA(address, line_index, str(update['line']))

        elif update_type == UpdateTypes.PosteriorLine:
            address = update['address']
            line_index = update['line_index']

            # in order for line i to be displayed all lines before i
            # must be non-empty
            for i in xrange(0, line_index):
                line = idc.LineB(address, i)
                if line is None or len(line) == 0:
                    idc.ExtLinB(address, i, " ")

            idc.ExtLinB(address, line_index, str(update['line']))

        elif update_type == UpdateTypes.LookHere:
            address = update['address']
            idc.Jump(address)
            should_remove_row = False

        else:
            print "WHAAAAAT does type %d mean in update %s?" % (update_type, str(update))
            return

        if should_remove_row:
            g_item_list_model.removeRow(row_index)

    finally:
        g_item_list_mutex.unlock()
        g_hooks_enabled = True
        return should_remove_row


def on_item_list_double_clicked(index):
    try:
        g_item_list_mutex.lock()
        row_index = index.row()
        apply_update(row_index)
        idc.Refresh()
    finally:
        g_item_list_mutex.unlock()


def add_item(message, description):
    try:
        g_item_list_mutex.lock()
        # print description
        item = QtGui.QStandardItem()
        item.setText(description)
        item.setData(message)
        item.setToolTip(description)

        if g_item_list_model.rowCount() >= MAX_ITEMS_IN_LIST:
            print "REMOVING"
            g_item_list_model.removeRow(0)

        g_item_list_model.appendRow(item)
    finally:
        g_item_list_mutex.unlock()


def update_form(message):
    try:
        g_item_list_mutex.lock()
        # print message
        message_type = message['type']
        address = message['address']

        if message_type == UpdateTypes.Name:
            new_name = message['name']
            current_name = idc.Name(address)

            if current_name == new_name:
                # not an update
                return

            if (current_name is not None) and (len(current_name) > 0) and (not common.is_default_name(current_name)):
                description = "Name [0x%x]: %s (YOURS: %s)" % (address, new_name, current_name)
            else:
                description = "Name [0x%x]: %s" % (address, new_name)
            add_item(message, description)

        elif message_type == UpdateTypes.Comment:
            new_comment = message['comment']
            current_comment = common.get_comment(address)

            if current_comment == new_comment:
                return

            if (current_comment is not None) and (len(current_comment) > 0):
                description = "Comment [0x%x]: %s\n(YOURS: %s)" % (address, new_comment, current_comment)
            else:
                description = "Comment [0x%x]: %s" % (address, new_comment)
            add_item(message, description)

        elif message_type == UpdateTypes.RepeatableComment:
            new_comment = message['comment']
            current_comment = common.get_repeated_comment(address)

            if current_comment == new_comment:
                return

            if (current_comment is not None) and (len(current_comment) > 0):
                description = "RComment [0x%x]: %s\n(YOURS: %s)" % (address, new_comment, current_comment)
            else:
                description = "RComment [0x%x]: %s" % (address, new_comment)
            add_item(message, description)

        elif message_type == UpdateTypes.AnteriorLine:
            new_line = message['line']
            line_index = message['line_index']
            current_line = idc.LineA(address, line_index)

            if new_line == current_line:
                return

            if (current_line is not None) and (len(current_line) > 0):
                description = "AntLine [0x%x] [%d]: %s\n(YOURS: %s)" % (address, line_index, new_line, current_line)
            else:
                description = "AntLine [0x%x] [%d]: %s" % (address, line_index, new_line)
            add_item(message, description)

        elif message_type == UpdateTypes.PosteriorLine:
            new_line = message['line']
            line_index = message['line_index']
            current_line = idc.LineB(address, line_index)

            if new_line == current_line:
                return

            if (current_line is not None) and (len(current_line) > 0):
                description = "PostLine [0x%x] [%d]: %s\n(YOURS: %s)" % (address, line_index, new_line, current_line)
            else:
                description = "PostLine [0x%x] [%d]: %s" % (address, line_index, new_line)
            add_item(message, description)

        elif message_type == UpdateTypes.LookHere:
            user = message['user']
            current_name = idc.Name(address)

            if (current_name is not None) and (len(current_name) > 0) and (not common.is_default_name(current_name)):
                description = "%s: look at 0x%x (YOUR NAME: %s)" % (user, address, current_name)
            else:
                description = "%s: look at 0x%x" % (user, address)

            add_item(message, description)

        else:
            print "WHAAAAAT does type %d mean in message %s?" % (message_type, str(message))

    finally:
        g_item_list_mutex.unlock()


class KeyPressFilter(QtCore.QObject):
    def eventFilter(self, receiver, event):
        if event.type() == QtCore.QEvent.KeyPress:
            if event.key() in [QtCore.Qt.Key_Backspace, QtCore.Qt.Key_Delete]:
                on_discard_button_clicked()
            elif event.key() in [QtCore.Qt.Key_Enter, QtCore.Qt.Key_Return]:
                on_apply_button_clicked()
            elif event.key() == QtCore.Qt.Key_Space:
                on_go_to_address_button_clicked()

        return super(KeyPressFilter, self).eventFilter(receiver, event)


class EscapeEater(QtCore.QObject):
    def eventFilter(self, receiver, event):
        if event.type() == QtCore.QEvent.KeyPress:
            if event.key() == QtCore.Qt.Key_Escape:
                return True
        return super(EscapeEater, self).eventFilter(receiver, event)


class SendPointerFromContextMenu(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        zmq_pub_json(ZMQ_PUB_CONNECTION_STRING, {'type': UpdateTypes.LookHere,
                                                 'address': idc.ScreenEA()})
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if ctx.form_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_FORM


class IDBPushUIHooks(idaapi.UI_Hooks):
    def finish_populating_tform_popup(self, form, popup):
        if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, CONTEXT_MENU_ACTION_NAME, None)


def install_ui_hooks():
    if not idaapi.register_action(idaapi.action_desc_t(
            CONTEXT_MENU_ACTION_NAME,  # must be unique
            "Send address via IDB Push",
            SendPointerFromContextMenu())):
        raise Exception("Failed to register action")

    global g_ui_hooks
    g_ui_hooks = IDBPushUIHooks()
    if not g_ui_hooks.hook():
        raise Exception("Failed to install UI hook")


def uninstall_ui_hooks():
    idaapi.unregister_action(CONTEXT_MENU_ACTION_NAME)

    global g_ui_hooks
    if g_ui_hooks is not None:
        g_ui_hooks.unhook()
        g_ui_hooks = None
