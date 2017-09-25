import traceback

import idc
import ida_struct
import ida_frame
import ida_bytes
import ida_lines
import ida_kernwin
from idaapi import PluginForm
from PyQt5 import QtGui, QtCore, QtWidgets

import idb_push_ops
import hooks
import psida_common

from idb_push_config import *
CONFIGURATION = get_configuration()

if CONFIGURATION[DEBUG]:
    reload(idb_push_ops)
    reload(hooks)
    reload(psida_common)

# Hols a unique identifier constructed from an update to the actual update object.
g_identifiers_to_updates = {}

# Global mutex for the item list
g_item_list_mutex = None
# The item list's model
g_item_list_model = None
# The item list
g_item_list = None
# The auto-apply checkbox
g_auto_apply_checkbox = None
# List of all make code update
g_make_code_updates_list = []


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

        discard_action = QtWidgets.QAction('Discard', self.items_list)
        discard_action.triggered.connect(on_discard_button_clicked)
        self.items_list.addAction(discard_action)

        go_to_address_action = QtWidgets.QAction('Go to address', self.items_list)
        go_to_address_action.triggered.connect(on_go_to_address_button_clicked)
        self.items_list.addAction(go_to_address_action)

        auto_apply_action = QtWidgets.QAction('Auto apply', self.items_list)
        auto_apply_action.triggered.connect(on_auto_apply_action_checked)
        self.items_list.addAction(auto_apply_action)

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

        auto_apply_checkbox = QtWidgets.QCheckBox('Auto apply no conflict')
        auto_apply_checkbox.clicked.connect(on_auto_apply_action_checked)
        layout.addWidget(auto_apply_checkbox)
        global g_auto_apply_checkbox
        g_auto_apply_checkbox = auto_apply_checkbox

        self.parent.setLayout(layout)
        if CONFIGURATION[AUTO_APPLY]:
            auto_apply_checkbox.click()

    def OnClose(self, _):
        self._terminate_callback()


def add_item(update):
    """
    Auto-applies, if the auto-apply checkbox is on.
    Otherwise:
    Adds a new item to the UI list.
    Updates the item if the unique identifier tuple already exists in the list.
    Deletes the oldest entries if the list exceeds @MAX_ITEMS_IN_LIST

    Args:
        update (IdbUpdate) - The update to be added to the UI list
    """
    if g_auto_apply_checkbox.isChecked():
        if not update.has_conflict():
            if CONFIGURATION[DEBUG]:
                print 'DEBUG - UI - Auto-applying an update without conflict: %s' % update
            apply_single_update(update)
            return
    try:
        g_item_list_mutex.lock()

        # handle special case of MakeCode updates
        if update.update_type == idb_push_ops.UpdateTypes.MakeCode:
            update = maybe_fix_make_code_update(update)
            if not update:
                return

        # make sure we don't have the same type of update to the
        # same address - if so, remove the old one!
        new_message_identifier = update.get_identifier()

        if new_message_identifier in g_identifiers_to_updates:
            # we have the same type of update for the same address
            old_update, old_description = g_identifiers_to_updates[new_message_identifier]
            matching_items = g_item_list_model.findItems(old_description)
            assert len(matching_items) == 1
            g_item_list_model.removeRow(matching_items[0].row())

        # print description
        item = QtGui.QStandardItem()
        item.setText(str(update))
        item.setData(update)
        item.setToolTip(str(update))

        if g_item_list_model.rowCount() >= CONFIGURATION[MAX_ITEMS_IN_LIST]:
            print 'INFO - UI - Limit of %d items reached - removing oldest entry' % CONFIGURATION[MAX_ITEMS_IN_LIST]
            doomed_update = g_item_list_model.item(0).data()

            g_item_list_model.removeRow(0)
            g_identifiers_to_updates.pop(doomed_update.get_identifier())

        g_item_list_model.appendRow(item)
        g_identifiers_to_updates[new_message_identifier] = (update, str(update))

    except:
        traceback.print_exc()
    finally:
        g_item_list_mutex.unlock()

    assert g_item_list_model.rowCount() == len(g_identifiers_to_updates)


def update_form(update):
    """ Processes an incoming update by adding it to the form.

    Args:
        update (IdbUpdate) - The message received from the ZMQ server, as a class that inherits IdbUpdate
    """
    try:
        g_item_list_mutex.lock()
        message_type = update.update_type
        address = update.address
        current_data = None

        if message_type == idb_push_ops.UpdateTypes.Name:
            current_data = psida_common.get_non_default_name(address, update.is_local)
            if current_data == update.data:
                return

        elif message_type == idb_push_ops.UpdateTypes.Comment:
            current_data = psida_common.get_comment(address)
            if current_data == update.data:
                return

        elif message_type == idb_push_ops.UpdateTypes.RepeatableComment:
            current_data = psida_common.get_repeated_comment(address)
            if current_data == update.data:
                return

        elif message_type in [idb_push_ops.UpdateTypes.AnteriorLine, idb_push_ops.UpdateTypes.PosteriorLine]:
            current_data = idc.get_extra_cmt(address, update.line_index)
            if current_data == update.data:
                return

        elif message_type == idb_push_ops.UpdateTypes.LookHere:
            current_data = psida_common.get_non_default_name(address)

        elif message_type == idb_push_ops.UpdateTypes.StackVariableRenamed:
            func_frame = ida_frame.get_frame(address)
            update.func_frame_pointer = func_frame
            member = ida_struct.get_member(func_frame, update.offset)
            current_data = None
            if member is not None:
                current_data = ida_struct.get_member_name(member.id)

            if current_data == update.data:
                return

            if current_data is not None:
                update.new = False
            else:
                update.new = True

        elif message_type in [idb_push_ops.UpdateTypes.MakeData, idb_push_ops.UpdateTypes.MakeCode]:
            current_data = update.get_conflict()
            if current_data == '':
                return

        else:
            if CONFIGURATION[DEBUG]:
                print 'DEBUG - UI - Unrecognized/Unimplemented type %d: in message %s' % (message_type, update.to_dict())
            return

        update.data_at_address = current_data
        add_item(update)
    except:
        if CONFIGURATION['debug']:
            traceback.print_exc()
        print 'ERROR - UI - General error while updating form'

    finally:
        g_item_list_mutex.unlock()


class KeyPressFilter(QtCore.QObject):
    """
    Declares handles on relevant key presses inside the UI (Enter, Return, Backspace, Delete, Space)
    """
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
    """
    Blocks escape key events from passing on to prevent the window from closing
    """
    def eventFilter(self, receiver, event):
        if event.type() == QtCore.QEvent.KeyPress:
            if event.key() == QtCore.Qt.Key_Escape:
                return True
        return super(EscapeEater, self).eventFilter(receiver, event)


def on_auto_apply_action_checked():
    # Save auto-apply state
    configure(auto_apply=g_auto_apply_checkbox.isChecked())


def on_item_list_double_clicked(index):
    """Calling `apply` when an item UI list was double clicked."""
    apply_update([index.row()])


def on_apply_button_clicked():
    """Calling `apply` on every update selected while pressing apply"""
    indices = [index.row() for index in g_item_list.selectedIndexes()]
    apply_update(indices)


def on_go_to_address_button_clicked():
    """Calling go_to on go to address button clicked."""
    try:
        g_item_list_mutex.lock()

        indices = g_item_list.selectedIndexes()
        if len(indices) != 1:
            print 'ERROR - UI - Can\'t go to more than one update at once'
            return

        index = indices[0].row()
        g_item_list_model.item(index).data().go_to()
    except:
        traceback.print_exc()
    finally:
        g_item_list_mutex.unlock()


def on_discard_button_clicked():
    """Removing item on discard button clicked."""
    try:
        g_item_list_mutex.lock()

        indices = [index.row() for index in g_item_list.selectedIndexes()]
        for i in sorted(indices, reverse=True):
            update = g_item_list_model.item(i).data()
            g_item_list_model.removeRow(i)
            g_identifiers_to_updates.pop(update.get_identifier())
    except:
        traceback.print_exc()
    finally:
        g_item_list_mutex.unlock()

    assert g_item_list_model.rowCount() == len(g_identifiers_to_updates)


def apply_single_update(update):
    """
    Applies a single update given the actual update instance

    :param update: (IdbUpdate) The update instance to update
    """
    successfully_executed = False
    try:
        hooks.g_hook_enabled = False
        update.apply()
        successfully_executed = True
    except:
        if CONFIGURATION['debug']:
            traceback.print_exc()
        pass
    finally:
        hooks.g_hooks_enabled = True

    if not successfully_executed:
        print 'ERROR - Update - Could not update: "%s"' % update


def apply_update(indices):
    """
    Calls the `apply` function on every update that needs to be applied, then removes said update.
    Because the removal happens after every apply, a fix is need to be done on the index to remove.

    :param indices: (list(int)) Indices in the item list of the updates that need to be applied
    """
    try:
        g_item_list_mutex.lock()

        removed_rows = 0
        # since every time you apply an update you discard it
        # AND you have to keep the update order you need to
        # track the offset for all indices after the one you just removed
        for i in sorted(indices):
            effective_index = i - removed_rows
            update_item = g_item_list_model.item(effective_index)
            update = update_item.data()

            successfully_executed = False
            should_remove_row = True
            try:
                hooks.g_hook_enabled = False
                should_remove_row = update.apply()
                successfully_executed = True
            except:
                if CONFIGURATION['debug']:
                    traceback.print_exc()
                pass
            finally:
                hooks.g_hooks_enabled = True

            if not successfully_executed:
                print 'ERROR - Update - Could not update: "%s"' % update_item.text()
            elif should_remove_row:
                g_item_list_model.removeRow(effective_index)
                g_identifiers_to_updates.pop(update.get_identifier())
                removed_rows += 1

        ida_kernwin.request_refresh(ida_kernwin.IWID_IDAMEMOS)
    except:
        traceback.print_exc()

    finally:
        g_item_list_mutex.unlock()


def maybe_fix_make_code_update(update):
    """

    :param update:
    :return:
    """

    # TODO: docstring. Maybe make this something generic for every update that has multiple changes? (Like deletion)

    for i in xrange(len(g_make_code_updates_list)):
        make_code_update = g_make_code_updates_list[i]
        if update.address - make_code_update.data == make_code_update.address:
            update.address = make_code_update.address
            update.data += make_code_update.data
            g_make_code_updates_list[i] = update
            return update

    for make_code_update in g_make_code_updates_list:
        if (update.address >= make_code_update.address and
                update.address + update.data <= make_code_update.address + make_code_update.data):
                return None
    g_make_code_updates_list.append(update)
    return update
