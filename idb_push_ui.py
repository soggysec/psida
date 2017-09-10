from idaapi import PluginForm
from PyQt5 import QtGui, QtCore, QtWidgets
import idb_push_ops
from idb_push_config import *
import traceback
import idc, ida_struct, ida_frame
import psida_common


# maps identifying properties of an update to the actual update object and its description
# for anterior and posterior lines the identifier is the triplet
# (address, update type, line index), for all other types it's
# (address, update type)
g_identifiers_to_updates = {}


# UI elements
g_item_list_mutex = None
g_item_list_model = None
g_item_list = None


class IDBPushForm(PluginForm):
    def __init__(self, terminate_callback):
        super(IDBPushForm, self).__init__()
        self._terminate_callback = terminate_callback

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

    def OnClose(self, _):
        self.terminate_callback()


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
        new_message_identifier = idb_push_ops.get_identifier(message)

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
            g_identifiers_to_updates.pop(idb_push_ops.get_identifier(doomed_update))

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

        if message_type == idb_push_ops.UpdateTypes.Name:
            new_name = message['name']
            current_name = psida_common.get_non_default_name(address)

            if current_name == new_name:
                return

            if current_name is not None:
                description = 'Name [0x%x]: %s (YOURS: %s)' % (address, new_name, current_name)
            else:
                description = 'Name [0x%x]: %s' % (address, new_name)
            add_item(message, description)

        elif message_type == idb_push_ops.UpdateTypes.Comment:
            new_comment = message['comment']
            current_comment = psida_common.get_comment(address)

            if current_comment == new_comment:
                return

            if (current_comment is not None) and (len(current_comment) > 0):
                description = 'Comment [0x%x]: %s\n(YOURS: %s)' % (address, new_comment, current_comment)
            else:
                description = 'Comment [0x%x]: %s' % (address, new_comment)
            add_item(message, description)

        elif message_type == idb_push_ops.UpdateTypes.RepeatableComment:
            new_comment = message['comment']
            current_comment = psida_common.get_repeated_comment(address)

            if current_comment == new_comment:
                return

            if (current_comment is not None) and (len(current_comment) > 0):
                description = 'RComment [0x%x]: %s\n(YOURS: %s)' % (address, new_comment, current_comment)
            else:
                description = 'RComment [0x%x]: %s' % (address, new_comment)
            add_item(message, description)

        elif message_type == idb_push_ops.UpdateTypes.AnteriorLine:
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

        elif message_type == idb_push_ops.UpdateTypes.PosteriorLine:
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

        elif message_type == idb_push_ops.UpdateTypes.LookHere:
            user = message['user']
            current_name = psida_common.get_non_default_name(address)

            if current_name is not None:
                description = '%s: look at 0x%x (YOUR NAME: %s)' % (user, address, current_name)
            else:
                description = '%s: look at 0x%x' % (user, address)

            add_item(message, description)

        elif message_type == idb_push_ops.UpdateTypes.StackVariableRenamed:

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

        elif (message_type == idb_push_ops.UpdateTypes.StructMemberRenamed or
                      message_type == idb_push_ops.UpdateTypes.StructMemberCreated):
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


def on_item_list_double_clicked(index):
    """Calling an update whenever an item on the UI list is double clicked. """
    apply_update([index.row()])


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


def apply_update(indices):
    try:
        g_item_list_mutex.lock()
        # indices = [index.row() for index in g_item_list.selectedIndexes()]

        removed_rows = 0
        # since every time you apply an update you discard it
        # AND you have to keep the update order you need to
        # track the offset for all indices after the one you just removed
        for i in sorted(indices):
            effective_index = i - removed_rows
            update = g_item_list_model.item(effective_index)
            update_data = psida_common.convert_struct_to_utf8(update.data())

            success, should_remove_row = idb_push_ops.apply_update_to_idb(update_data)
            if not success:
                print 'ERROR - Update - Could not update: "%s"' % update.text()
            elif should_remove_row:
                g_item_list_model.removeRow(effective_index)
                g_identifiers_to_updates.pop(idb_push_ops.get_identifier(update_data))
                removed_rows += 1

        idc.Refresh()
    except:
        traceback.print_exc()

    finally:
        g_item_list_mutex.unlock()


def on_apply_button_clicked():
    indices = [index.row() for index in g_item_list.selectedIndexes()]
    apply_update(indices)


def on_discard_button_clicked():
    try:
        g_item_list_mutex.lock()

        indices = [index.row() for index in g_item_list.selectedIndexes()]
        for i in sorted(indices, reverse=True):
            update = g_item_list_model.item(i).data()

            g_item_list_model.removeRow(i)
            g_identifiers_to_updates.pop(idb_push_ops.get_identifier(update))

    except:
        traceback.print_exc()

    finally:
        g_item_list_mutex.unlock()

    assert g_item_list_model.rowCount() == len(g_identifiers_to_updates)