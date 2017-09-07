import os
import idaapi
import psida_common
import traceback
import json
import time
from idaapi import PluginForm
import idc
import ida_struct
import ida_frame
import ida_nalt
import random
from socket import gethostbyname
import pprint

from PyQt5 import QtGui, QtCore, QtWidgets

try:
    import zmq
except ImportError:
    print 'WARNING - Import - zmq not found, idb_push will not function properly'
    zmq = None

CONTEXT_MENU_ACTION_NAME = 'idb_push:send_address'

CONNECTION_STRING_FORMAT = r'tcp://%s:%d'

CONFIG_FILE_NAME = os.path.join(os.path.expandvars(r'%APPDATA%\Hex-Rays\IDA Pro'), r'idb_push.cfg')

USER = 'user'
BACKEND_HOSTNAME = 'backend_hostname'
SUB_PORT = 'sub_port'
PUB_PORT = 'pub_port'
ZMQ_TIMEOUT_MS = 'timeout'
MAX_ITEMS_IN_LIST = 'max_items'
DEBUG = 'debug'
ZMQ_CONNECTIVITY_TEST_TIMEOUT_MS = 'connectivity_test_timeout'

# filled with reasonable defaults
CONFIGURATION = {
    USER: os.getenv('COMPUTERNAME'),
    BACKEND_HOSTNAME: '',
    SUB_PORT: 5560,
    PUB_PORT: 5559,
    ZMQ_TIMEOUT_MS: 100,
    ZMQ_CONNECTIVITY_TEST_TIMEOUT_MS: 1000,
    MAX_ITEMS_IN_LIST: 1000,
    DEBUG: False
}
    
class UpdateTypes(object):
    Name, Comment, RepeatableComment, AnteriorLine, PosteriorLine, LookHere, StackVariableRenamed, StructMemberCreated, StructMemberRenamed = range(9)


def store_configuration():
    with open(CONFIG_FILE_NAME, 'w') as f:
        json.dump(CONFIGURATION, f)


def load_configuration():
    global CONFIGURATION

    with open(CONFIG_FILE_NAME) as f:
        CONFIGURATION = json.load(f)


def configure(backend_hostname=None,
              pub_port=None,
              sub_port=None,
              timeout=None,
              connectivity_test_timeout=None,
              max_items=None,
              user=None,
              debug=None):
    global CONFIGURATION

    # Try resolving the backend_hostname to IPv4.
    # 'gethostbyname' only supports IPv4, which is nice.
    # If the given string is an IP address, 'gethostbyname' returns it, which is also nice.
    if backend_hostname:
        backend_hostname = gethostbyname(backend_hostname)

    # since this is a dictionary, all the arguments
    # that are None will overwrite one another -
    # and we don't mind at all
    arguments_to_names = {backend_hostname: BACKEND_HOSTNAME,
                          pub_port: PUB_PORT,
                          sub_port: SUB_PORT,
                          timeout: ZMQ_TIMEOUT_MS,
                          connectivity_test_timeout: ZMQ_CONNECTIVITY_TEST_TIMEOUT_MS,
                          max_items: MAX_ITEMS_IN_LIST,
                          user: USER,
                          debug: DEBUG}

    for (argument, name) in arguments_to_names.iteritems():
        if argument is None:
            continue
        CONFIGURATION[name] = argument

    store_configuration()

class ZMQConnectionException(BaseException):
    pass
    
def zmq_test_connectivity():
    """Creates a temporary ZMQ socket and tests server connectivity"""

    pub_connection_string = r"tcp://%s:%d" % (CONFIGURATION[BACKEND_HOSTNAME],
                                              CONFIGURATION[PUB_PORT])
    sub_connection_string = r"tcp://%s:%d" % (CONFIGURATION[BACKEND_HOSTNAME],
                                              CONFIGURATION[SUB_PORT])

    context = zmq.Context()
    random.seed()

    rx_end_time = time.time() + (CONFIGURATION[ZMQ_CONNECTIVITY_TEST_TIMEOUT_MS] / 1000.0)
    found_random_string = False

    while time.time() < rx_end_time:
        try:
            # open a transmitting socket
            tx_socket = context.socket(zmq.PUB)
            tx_socket.setsockopt(zmq.LINGER, CONFIGURATION[ZMQ_TIMEOUT_MS])
            tx_socket.connect(pub_connection_string)
            topic = "0"  # dummy

            # open a receiving socket
            rx_socket = context.socket(zmq.SUB)
            rx_socket.connect(sub_connection_string)
            rx_socket.setsockopt(zmq.SUBSCRIBE, "")
            rx_socket.RCVTIMEO = CONFIGURATION[ZMQ_TIMEOUT_MS]

            # sleep to allow both sockets to connect
            time.sleep(CONFIGURATION[ZMQ_TIMEOUT_MS] / 1000.0)

            # send a random test packet
            random_string = "%010x" % random.randrange(16 ** 10)
            tx_socket.send_multipart([topic, json.dumps(random_string)])

            # wait for a while for the reply to arrive
            _, message = rx_socket.recv_multipart()
            tx_socket.close()
            rx_socket.close()

            if random_string in message:
                found_random_string = True
                break

        except zmq.error.Again:
            # timeout - that's OK
            continue

    if not found_random_string:
        raise ZMQConnectionException('ZMQ connectivity test failed!')

def open_zmq_socket():
    global g_zmq_socket
    try:
        context = zmq.Context()
        g_zmq_socket = context.socket(zmq.PUB)
        g_zmq_socket.setsockopt(zmq.LINGER, CONFIGURATION[ZMQ_TIMEOUT_MS])

        connection_string = CONNECTION_STRING_FORMAT % (CONFIGURATION[BACKEND_HOSTNAME],
                                                        CONFIGURATION[PUB_PORT])
        g_zmq_socket.connect(connection_string)
    except zmq.ZMQBaseError:
        if CONFIGURATION['debug']:
            traceback.print_exc()
        raise Exception('Error in creating ZMQ socket')

def restart_zmq_socket():
    close_zmq_socket()
    open_zmq_socket()

def close_zmq_socket():
    global g_zmq_socket
    try:
        g_zmq_socket.close()
    except:
        pass
    del g_zmq_socket
    g_zmq_socket = None

def zmq_pub_json(json_message):
    global g_zmq_socket
    try:
        if 'user' not in json_message:
            json_message['user'] = CONFIGURATION[USER]
        if 'project' not in json_message:
            json_message['project'] = os.path.basename(idc.GetIdbPath())
        
        topic = '0'  # dummy
        g_zmq_socket.send_multipart([topic, json.dumps(json_message)])

        if CONFIGURATION['debug']:
            print 'DEBUG - SendThread - Sent message\r\n%s' % pprint.pformat(json_message)

    except zmq.ZMQBaseError:
        if CONFIGURATION['debug']:
                traceback.print_exc()
        raise Exception('Error in sending message in ZMQ socket')


class IDPHook(idaapi.IDP_Hooks):
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def renamed(self, ea, new_name, local_name):
        if CONFIGURATION['debug']:
            print 'DEBUG - Hooks - RenameIDPHook.renamed(ea = 0x%x, new_name = %s, local_name = %r)' % (ea, new_name, local_name)


        if ida_struct.is_member_id(ea):
            # Change is either a built-in struct of a frame pointer, or some address starting with 0xFF00 that happens to be a member address.
            # if CONFIGURATION['debug']:
            print 'INFO - Hooks - RenameIDPHook - Skipping a possible stack variable/built-in struct change'
            return idaapi.IDP_Hooks.renamed(self, ea, new_name, local_name)

        if (g_hooks_enabled and
                (new_name is not None) and
                (len(new_name) > 0) and
                (not psida_common.is_default_name(new_name))):
            zmq_pub_json({'type': UpdateTypes.Name,
                          'address': ea,
                          'name': new_name,
                          'local_name': local_name})

        return idaapi.IDP_Hooks.renamed(self, ea, new_name, local_name)


class IDBHook(idaapi.IDB_Hooks):
    def __init__(self):
        idaapi.IDB_Hooks.__init__(self)

    def cmt_changed(self, ea, is_repeatable):
        if CONFIGURATION['debug']:
            print 'DEBUG - Hooks - CommentIDBHook.cmt_changed(arg0 = 0x%x, is_repeatable = %s)' % (ea, is_repeatable)
        
        message = {'address': ea}

        if is_repeatable:
            message['type'] = UpdateTypes.RepeatableComment
            message['comment'] = psida_common.get_repeated_comment(ea)
        else:
            message['type'] = UpdateTypes.Comment
            message['comment'] = psida_common.get_comment(ea)

        if g_hooks_enabled and (message['comment'] is not None) and (len(message['comment']) > 0):
            zmq_pub_json(message)

        return idaapi.IDB_Hooks.cmt_changed(self, ea, is_repeatable)

    def area_cmt_changed(self, areas, area, comment, is_repeatable):
        if CONFIGURATION['debug']:
            print 'DEBUG - Hooks - CommentIDBHook.area_cmt_changed(area_start = 0x%x, comment = %s)' % (area.startEA, comment)

        ea = area.startEA
        message = {'address': ea}

        if is_repeatable:
            message['type'] = UpdateTypes.RepeatableComment
            message['comment'] = psida_common.get_repeated_comment(ea)
        else:
            message['type'] = UpdateTypes.Comment
            message['comment'] = psida_common.get_comment(ea)

        if g_hooks_enabled and (message['comment'] is not None) and (len(message['comment']) > 0):
            zmq_pub_json(message)

        return idaapi.IDB_Hooks.area_cmt_changed(self, areas, area, comment, is_repeatable)

    def extra_cmt_changed(self, ea, line_idx, cmt):
        if CONFIGURATION['debug']:
            print 'DEBUG - Hooks - CommentIDBHook.extra_cmt_changed(ea = 0x%x, line_idx = %d, cmt = %s)' % (ea, line_idx, cmt)

        message = {'address': ea, 'line': cmt}

        if idaapi.E_PREV <= line_idx < idaapi.E_NEXT:
            message['type'] = UpdateTypes.AnteriorLine
            message['line_index'] = line_idx - idaapi.E_PREV
        elif line_idx >= idaapi.E_NEXT:
            message['type'] = UpdateTypes.PosteriorLine
            message['line_index'] = line_idx - idaapi.E_NEXT
        else:
            if CONFIGURATION['debug']:
                print 'DEBUG - Hooks - CommentIDBHook.extra_cmt_changed - unexpected line_idx, continuing...'
            return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)

        if g_hooks_enabled and (message['line'] is not None) and (len(message['line']) > 0):
            zmq_pub_json(message)

        return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)

    def struc_member_created(self, sptr, mptr):
        if CONFIGURATION['debug']:
            print 'DEBUG - Hooks - StructIDBHook.struc_member_created(sptr = %s, mptr = %s)' % (pprint.pformat(sptr), pprint.pformat(mptr))

        message = { 'type': UpdateTypes.StructMemberCreated,
                    'name': ida_struct.get_member_name(mptr.id), 
                    'address': ida_frame.get_func_by_frame(sptr.id),
                    'offset': mptr.soff,
                    'var_size': mptr.eoff - mptr.soff}

        if sptr.props & 0x40: # Struct changed is a frame pointer
            message['type'] = UpdateTypes.StackVariableRenamed

        if g_hooks_enabled and (message['name'] is not None) and (len(message['name']) > 0):
            zmq_pub_json(message)

        return idaapi.IDB_Hooks.struc_member_created(self, sptr, mptr)

    def struc_member_renamed(self, sptr, mptr):
        if CONFIGURATION['debug']:
            print 'DEBUG - Hooks - StructIDBHook.struc_member_renamed(sptr = %s, mptr = %s)' % (pprint.pformat(sptr), pprint.pformat(mptr))

        message = { 'type': UpdateTypes.StructMemberRenamed,
                    'name': ida_struct.get_member_name(mptr.id), 
                    'address': ida_frame.get_func_by_frame(sptr.id),
                    'offset': mptr.soff,
                    'var_size': mptr.eoff - mptr.soff}

        if sptr.props & 0x40: # Struct changed is a frame pointer
            message['type'] = UpdateTypes.StackVariableRenamed
        
        if g_hooks_enabled and (message['name'] is not None) and (len(message['name']) > 0):
            zmq_pub_json(message)   
     
        return idaapi.IDB_Hooks.struc_member_renamed(self, sptr, mptr)

# globals
# TODO: Deal with socket closing unexpectedly (Server throwing a RST, computer sleeping, etc.)
g_zmq_socket = None
g_idp_hook = IDPHook()
g_idb_hook = IDBHook()
g_ui_hooks = None
g_hooks_enabled = False
g_receive_thread = None
g_item_list_mutex = None
g_item_list_model = None
g_item_list = None
g_form = None

# maps identifying properties of an update to the actual update object and its description
# for anterior and posterior lines the identifier is the triplet
# (address, update type, line index), for all other types it's
# (address, update type)
g_identifiers_to_updates = {}

def get_identifier(update_json):
    update_type = update_json['type']
    address = update_json['address']

    if update_type in [UpdateTypes.AnteriorLine,
                       UpdateTypes.PosteriorLine]:
        return address, update_type, update_json['line_index']

    elif update_type == UpdateTypes.StackVariableRenamed:
        return address, update_type, update_json['offset']

    return address, update_type


class ReceiveThread(QtCore.QThread):
    def __init__(self):
        super(ReceiveThread, self).__init__()
        self._should_stop = False
        self._connection_string = r'tcp://%s:%d' % (CONFIGURATION[BACKEND_HOSTNAME],
                                                    CONFIGURATION[SUB_PORT])
        self._context = zmq.Context()

        self._socket = self._context.socket(zmq.SUB)
        self._socket.connect(self._connection_string)
        self._socket.setsockopt(zmq.SUBSCRIBE, '')
        self._socket.RCVTIMEO = CONFIGURATION[ZMQ_TIMEOUT_MS]

    def signal_stop(self):
        self._should_stop = True

    def run(self):
        while True:
            if self._should_stop:
                return
            try:
                _, json_message = self._socket.recv_multipart()
                message = json.loads(json_message)
                if message is None or len(message) == 0:
                    continue

                message = psida_common.convert_struct_to_utf8(message)

                if 'user' not in message or message['user'] == CONFIGURATION[USER]:
                    # don't receive your own updates
                    continue
                if ('project' not in message or
                            message['project'] != os.path.basename(idc.GetIdbPath())):
                    # don't receive updates for other projects
                    continue

                if CONFIGURATION['debug']:
                    print 'DEBUG - ReceiveThread - Recieved message %s' % pprint.pformat(message)

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
                self._socket.setsockopt(zmq.SUBSCRIBE, '')
                self._socket.RCVTIMEO = CONFIGURATION[ZMQ_TIMEOUT_MS]


def start():
    print 'INFO - Configuration - \r\n' + pprint.pformat(CONFIGURATION)

    # test connectivity
    zmq_test_connectivity()
    # open global socket
    open_zmq_socket()

    if not g_idp_hook.hook():
        raise Exception('RenameIDPHook installation FAILED')

    if not g_idb_hook.hook():
        raise Exception('CommentIDBHook installation FAILED')

    global g_hooks_enabled
    g_hooks_enabled = True

    global g_receive_thread
    g_receive_thread = ReceiveThread()
    g_receive_thread.start()

    global g_form
    g_form = IDBPushForm()
    g_form.Show('IDB PUSH')

    install_ui_hooks()

    # register for when IDA terminates
    idaapi.notify_when(idaapi.NW_TERMIDA, stop)


def _remove_hooks_and_stop_thread():
    global g_hooks_enabled
    g_hooks_enabled = False
    g_idp_hook.unhook()
    g_idb_hook.unhook()

    global g_receive_thread
    if g_receive_thread is not None:
        g_receive_thread.signal_stop()

    uninstall_ui_hooks()

def restart():
    stop()
    start()

def stop(reason=None):
    close_zmq_socket()
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
            print 'ERROR - UI - Can\'t go to more than one update at once'
            return

        index = indices[0].row()
        address = g_item_list_model.item(index).data()['address']
        idc.Jump(address)
    except:
        traceback.print_exc()
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
    except:
        traceback.print_exc()

    finally:
        g_item_list_mutex.unlock()


def on_discard_button_clicked():
    try:
        g_item_list_mutex.lock()

        indices = [index.row() for index in g_item_list.selectedIndexes()]
        for i in sorted(indices, reverse=True):
            update = g_item_list_model.item(i).data()

            g_item_list_model.removeRow(i)
            g_identifiers_to_updates.pop(get_identifier(update))

    except:
        traceback.print_exc()

    finally:
        g_item_list_mutex.unlock()

    assert g_item_list_model.rowCount() == len(g_identifiers_to_updates)


def apply_update(row_index):
    """Applies the update from the IDB PUSH window at row_index

    Args:
        row_index (int): Index of the row to apply the update from

    Returns:
        bool: Whether applying the change was successful and the row was removed.
    """
    global g_hooks_enabled
    should_remove_row = True

    try:
        g_item_list_mutex.lock()
        g_hooks_enabled = False
        # apply update
        update = g_item_list_model.item(row_index).data()
        update = psida_common.convert_struct_to_utf8(update)
        update_type = update['type']
        address = update['address']

        if update_type == UpdateTypes.Name:

            name = update['name']
            local_name = bool(update['local_name'])
            if not psida_common.set_name(address, name, local_name):
                print 'ERROR - Update - Failed to name 0x%x as %s' % (address, name)
                should_remove_row = False

        elif update_type == UpdateTypes.Comment:
            comment = update['comment']
            psida_common.set_comment(address, comment)

        elif update_type == UpdateTypes.RepeatableComment:
            comment = update['comment']
            psida_common.set_repeated_comment(address, comment)

        elif update_type == UpdateTypes.AnteriorLine:
            line_index = update['line_index']
            # in order for line i to be displayed all lines before i
            # must be non-empty
            for i in xrange(0, line_index):
                line = idc.LineA(address, i)
                if line is None or len(line) == 0:
                    idc.ExtLinA(address, i, " ")

            idc.ExtLinA(address, line_index, update['line'])

        elif update_type == UpdateTypes.PosteriorLine:
            line_index = update['line_index']

            # in order for line i to be displayed all lines before i
            # must be non-empty
            for i in xrange(0, line_index):
                line = idc.LineB(address, i)
                if line is None or len(line) == 0:
                    idc.ExtLinB(address, i, ' ')

            idc.ExtLinB(address, line_index, update['line'])

        elif update_type == UpdateTypes.LookHere:
            idc.Jump(address)
            should_remove_row = False

        elif update_type == UpdateTypes.StackVariableRenamed:
            func_frame = update['func_frame_ptr']
            offset = update['offset']
            name = update['name']
            if update['new']:
                ida_struct.add_struc_member(func_frame, name, offset, 0, ida_nalt.opinfo_t(), update['var_size'])
            else:
                ida_struct.set_member_name(func_frame, offset, name)

        else:
            if CONFIGURATION['debug']:
                print 'DEBUG - Update - Unrecognized type %d: update %s' % (update_type, update)
            return

        if should_remove_row:
            g_item_list_model.removeRow(row_index)
            g_identifiers_to_updates.pop(get_identifier(update))
    except:
        traceback.print_exc()

    finally:
        g_item_list_mutex.unlock()
        g_hooks_enabled = True

    assert g_item_list_model.rowCount() == len(g_identifiers_to_updates)
    return should_remove_row


def on_item_list_double_clicked(index):
    """Calling an update whenever an item on the UI list is double clicked. """
    try:
        g_item_list_mutex.lock()
        row_index = index.row()
        apply_update(row_index)
        idc.Refresh()
    except:
        traceback.print_exc()
    finally:
        g_item_list_mutex.unlock()


def add_item(message, description):
    """Adds a new item to the UI list.
    Updates the item if the unique identifier tuple already exists in the list.
    Deletes the oldest entries if the list exceeds @MAX_ITEMS_IN_LIST

    Args:
        message (dict) - The data to be connected to the item in the UI list.
        description (str) - The string to display on the list.

    """
    try:
        g_item_list_mutex.lock()
        # make sure we don't have the same type of update to the
        # same address - if so, remove the old one!
        new_message_identifier = get_identifier(message)

        if new_message_identifier in g_identifiers_to_updates:
            # we have the same type of update for the same address
            old_update, old_description = g_identifiers_to_updates[new_message_identifier]
            matching_items = g_item_list_model.findItems(old_description)
            assert len(matching_items) == 1
            g_item_list_model.removeRow(matching_items[0].row())

        # print description
        item = QtGui.QStandardItem()
        item.setText(description)
        item.setData(message)
        item.setToolTip(description)

        if g_item_list_model.rowCount() >= CONFIGURATION[MAX_ITEMS_IN_LIST]:
            print 'INFO - UI - Limit of %d items reached - removing oldest entry' % CONFIGURATION[MAX_ITEMS_IN_LIST]
            doomed_update = g_item_list_model.item(0).data()

            g_item_list_model.removeRow(0)
            g_identifiers_to_updates.pop(get_identifier(doomed_update))

        g_item_list_model.appendRow(item)
        g_identifiers_to_updates[new_message_identifier] = (message, description)

    except:
        traceback.print_exc()
    finally:
        g_item_list_mutex.unlock()

    assert g_item_list_model.rowCount() == len(g_identifiers_to_updates)


def update_form(message):
    """ Processes a new coming update by building a relevant description 
        depending on the message type and adding it to the list.

    Args:
        message (dict) - The message received from the ZMQ server
    """
    try:
        g_item_list_mutex.lock()
        message_type = message['type']
        address = message['address']

        if message_type == UpdateTypes.Name:
            new_name = message['name']
            current_name = psida_common.get_non_default_name(address)

            if current_name == new_name:
                return

            if current_name is not None:
                description = 'Name [0x%x]: %s (YOURS: %s)' % (address, new_name, current_name)
            else:
                description = 'Name [0x%x]: %s' % (address, new_name)
            add_item(message, description)

        elif message_type == UpdateTypes.Comment:
            new_comment = message['comment']
            current_comment = psida_common.get_comment(address)

            if current_comment == new_comment:
                return

            if (current_comment is not None) and (len(current_comment) > 0):
                description = 'Comment [0x%x]: %s\n(YOURS: %s)' % (address, new_comment, current_comment)
            else:
                description = 'Comment [0x%x]: %s' % (address, new_comment)
            add_item(message, description)

        elif message_type == UpdateTypes.RepeatableComment:
            new_comment = message['comment']
            current_comment = psida_common.get_repeated_comment(address)

            if current_comment == new_comment:
                return

            if (current_comment is not None) and (len(current_comment) > 0):
                description = 'RComment [0x%x]: %s\n(YOURS: %s)' % (address, new_comment, current_comment)
            else:
                description = 'RComment [0x%x]: %s' % (address, new_comment)
            add_item(message, description)

        elif message_type == UpdateTypes.AnteriorLine:
            new_line = message['line']
            line_index = message['line_index']
            current_line = idc.LineA(address, line_index)

            if new_line == current_line:
                return

            if (current_line is not None) and (len(current_line) > 0):
                description = 'AntLine [0x%x] [%d]: %s\n(YOURS: %s)' % (address, line_index, new_line, current_line)
            else:
                description = 'AntLine [0x%x] [%d]: %s' % (address, line_index, new_line)
            add_item(message, description)

        elif message_type == UpdateTypes.PosteriorLine:
            new_line = message['line']
            line_index = message['line_index']
            current_line = idc.LineB(address, line_index)

            if new_line == current_line:
                return

            if (current_line is not None) and (len(current_line) > 0):
                description = 'PostLine [0x%x] [%d]: %s\n(YOURS: %s)' % (address, line_index, new_line, current_line)
            else:
                description = 'PostLine [0x%x] [%d]: %s' % (address, line_index, new_line)
            add_item(message, description)

        elif message_type == UpdateTypes.LookHere:
            user = message['user']
            current_name = psida_common.get_non_default_name(address)

            if current_name is not None:
                description = '%s: look at 0x%x (YOUR NAME: %s)' % (user, address, current_name)
            else:
                description = '%s: look at 0x%x' % (user, address)

            add_item(message, description)

        elif message_type == UpdateTypes.StackVariableRenamed:

            func_ea = message['address']
            func_frame = ida_frame.get_frame(func_ea)
            message['func_frame_ptr'] = func_frame
            member = ida_struct.get_member(func_frame, message['offset'])
            current_name = None
            if member is not None:
                current_name = ida_struct.get_member_name(member.id)
            new_name = message['name']

            if new_name == current_name:
                return

            if (current_name is not None):
                message['new'] = False
                description = 'StackVar [At Func: 0x%x]: %s\n(YOURS: %s)' % (func_ea, new_name, current_name)
            else:
                message['new'] = True
                description = 'StackVar [At Func: 0x%x]: %s\n(At offset: 0x%x)' % (func_ea, new_name, message['offset'])

            add_item(message, description)

        elif message_type == UpdateTypes.StructMemberRenamed or message_type == UpdateTypes.StructMemberCreated:
            if CONFIGURATION['debug']:
                print 'DEBUG - UI - Unimplemented message sent: %s' % (message_type)

        else:
            if CONFIGURATION['debug']:
                print 'DEBUG - UI - Unrecognized type %d: in message %s' % (message_type, str(message))
    except:
        traceback.print_exc()

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
        zmq_pub_json({'type': UpdateTypes.LookHere,
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
            'Send address via IDB Push',
            SendPointerFromContextMenu())):
        raise Exception('Failed to register action')

    global g_ui_hooks
    g_ui_hooks = IDBPushUIHooks()
    if not g_ui_hooks.hook():
        raise Exception('Failed to install UI hook')


def uninstall_ui_hooks():
    idaapi.unregister_action(CONTEXT_MENU_ACTION_NAME)

    global g_ui_hooks
    if g_ui_hooks is not None:
        g_ui_hooks.unhook()
        g_ui_hooks = None


# load from the configuration file -
# and create it if necessary
try:
    if os.path.isfile(CONFIG_FILE_NAME):
        # read from the configuration file
        load_configuration()
    else:
        # create a configuration file
        # with default values
        store_configuration()

except:
    print 'ERROR - Configuration - Couldn\'t load or create the configuration file'
    if CONFIGURATION['debug']:
        traceback.print_exc()
