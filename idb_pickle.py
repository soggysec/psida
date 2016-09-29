import cPickle
import time
import common
import idb_push
import idc
import idaapi
import idautils
import traceback
from idaapi import PluginForm

from PyQt5 import QtGui, QtCore, QtWidgets

# names in pickled dictionary
INPUT_FILE_MD5_FIELD = 'MD5'
SEGMENT_WARNING = "Segment mismatch - unpickled file has segments:\n%s\n\nwhile you have:\n%s\n\nContinue anyway?"
NAMES_FIELD = 'NAMES'
SEGMENTS = 'SEGMENTS'
COMMENTS_FIELD = 'COMMENTS'

# UI globals
g_item_list_model = None
g_item_list = None
g_form = None


class ItemType(object):
    Name, Comment, RepeatableComment, AnteriorLines, PosteriorLines = range(5)


def format_segments(segments_set):
    return '\n'.join([('%s: [%s, %s]' % (s[0], hex(s[1]), hex(s[2]))) for s in segments_set])


def get_names():
    """
    Returns a dictionary of {address -> name).
    """
    names_dictionary = {}

    segments = common.get_segments()
    for _, address, end_address in segments:

        while address < end_address:
            name = common.get_non_default_name(address)
            if name is not None:
                names_dictionary[address] = name
            address += idc.ItemSize(address)

    return names_dictionary


def get_function_names():
    """
    Returns a dictionary of (address -> name), limited
    to function names.
    """
    names_dictionary = {}

    for address in idautils.Functions():
        name = common.get_non_default_name(address)
        if name is not None:
            names_dictionary[address] = name

    return names_dictionary


def set_names(names_dictionary, overwrite=False, conflicts=None):
    for address, new_name in names_dictionary.iteritems():
        current_name = common.get_non_default_name(address)
        if new_name == current_name:
            continue
        elif overwrite or current_name is None:
            if not common.set_name(address, new_name):
                print "Failed to set name %s to address %s" % (new_name, hex(address))
        else:
            if conflicts is None:
                print "Naming conflict at %s: NEW: %s CURRENT: %s" % (hex(address), new_name, current_name)
                continue
            else:
                # update the conflicts dictionary
                conflicts[address] = new_name


# All getters receive address and return the value (or None in case there is no value).
# All setters receive address and value and print an error message in case of failure.


def __get_lines(address, getter):
    lines = []

    line_number = 0
    line = getter(address, line_number)

    while line is not None:
        lines.append(line)
        line_number += 1
        line = getter(address, line_number)

    if len(lines) == 0:
        return None
    return lines


def get_anterior_lines(address):
    return __get_lines(address, idc.LineA)


def get_posterior_lines(address):
    return __get_lines(address, idc.LineB)


def __set_lines(address, setter, lines):
    if lines is None:
        return
    for i in xrange(len(lines)):
        setter(address, i, lines[i])


def set_anterior_lines(address, lines):
    __set_lines(address, idc.ExtLinA, lines)


def set_posterior_lines(address, lines):
    __set_lines(address, idc.ExtLinB, lines)


def get_all_comments():
    """
    Returns a dictionary of {address -> (normal comment, repeated comment,
    anterior lines list, posterior lines list) }.
    """
    comments = {}

    segments_set = common.get_segments()
    for _, address, end_address in segments_set:
        while address < end_address:
            normal_comment = common.get_comment(address)
            repeated_comment = common.get_repeated_comment(address)
            anterior_lines = get_anterior_lines(address)
            posterior_lines = get_posterior_lines(address)

            if ((normal_comment, repeated_comment, anterior_lines, posterior_lines) !=
                    (None, None, None, None)):
                comments[address] = (normal_comment, repeated_comment, anterior_lines, posterior_lines)

            address += idc.ItemSize(address)

    return comments


def __set_comments(comments_dictionary, overwrite, content_index, getter, setter, conflict_message, conflicts=None):
    """
    Tricky internal function.

    EDIT: I now realise this is really bad documentation.
    """
    for address, comments_tuple in comments_dictionary.iteritems():
        new_content = comments_tuple[content_index]
        if new_content is None:
            continue
        current_content = getter(address)
        if current_content == new_content:
            continue
        if overwrite or current_content is None:
            setter(address, new_content)
        else:
            if conflicts is None:
                print conflict_message % (hex(address), new_content, current_content)
                continue
            else:
                # add only this particular conflict, since the others may be OK
                conflict = list(conflicts.get(address, (None,) * 4))
                conflict[content_index] = new_content
                conflicts[address] = tuple(conflict)


def set_all_comments(comments_dictionary, overwrite=False, conflicts=None):
    __set_comments(comments_dictionary,
                   overwrite,
                   0,
                   common.get_comment,
                   common.set_comment,
                   "Normal comment conflict at %s: NEW: %s CURRENT: %s",
                   conflicts)

    __set_comments(comments_dictionary,
                   overwrite,
                   1,
                   common.get_repeated_comment,
                   common.set_repeated_comment,
                   "Repeated comment conflict at %s: NEW: %s CURRENT: %s",
                   conflicts)

    __set_comments(comments_dictionary,
                   overwrite,
                   2,
                   get_anterior_lines,
                   set_anterior_lines,
                   "Anterior lines conflict at %s: NEW: %s CURRENT: %s",
                   conflicts)

    __set_comments(comments_dictionary,
                   overwrite,
                   3,
                   get_posterior_lines,
                   set_posterior_lines,
                   "Posterior lines conflict at %s: NEW: %s CURRENT: %s",
                   conflicts)


def pickle(destination_file=None, functions_only=False):
    """
    Stores some of the information in the IDB in
    the given file in pickle format - a dictionary of:
     - MD5 of binary input file
     - segment names and ranges
     - function and address names
     - comments
    """
    if destination_file is None:
        destination_file = QtWidgets.QFileDialog.getSaveFileName()[0]

    print "Started pickling at %s" % (time.ctime())
    idb_data = {INPUT_FILE_MD5_FIELD: idc.GetInputMD5(),
                SEGMENTS: common.get_segments(),
                }

    if functions_only:
        idb_data[NAMES_FIELD] = get_function_names()
        idb_data[COMMENTS_FIELD] = {}
    else:
        idb_data[NAMES_FIELD] = get_names()
        idb_data[COMMENTS_FIELD] = get_all_comments()

    # pickle the data
    with open(destination_file, 'wb') as f:
        cPickle.dump(idb_data, f, 2)

    print "Pickling complete at %s" % (time.ctime())


class EscapeEater(QtCore.QObject):
    def eventFilter(self, receiver, event):
        if event.type() == QtCore.QEvent.KeyPress:
            if event.key() == QtCore.Qt.Key_Escape:
                return True
        return super(EscapeEater, self).eventFilter(receiver, event)


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


class IDBMergeForm(PluginForm):
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


def add_item_to_form(item, description):
    ui_item = QtGui.QStandardItem()
    ui_item.setText(description)
    ui_item.setData(item)
    ui_item.setToolTip(description)

    g_item_list_model.appendRow(ui_item)


def populate_form_with_items(items):
    # Fills g_item_list_model with textual representations
    # of the unpickled items.

    for item in items:
        item_type = item['type']
        address = item['address']

        if item_type == ItemType.Name:
            new_name = item['name']
            current_name = common.get_non_default_name(address)

            if current_name == new_name:
                continue

            if current_name is not None:
                description = "Name [0x%x]: %s (YOURS: %s)" % (address, new_name, current_name)
            else:
                description = "Name [0x%x]: %s" % (address, new_name)

        elif item_type == ItemType.Comment:
            new_comment = item['comment']
            current_comment = common.get_comment(address)

            if new_comment is None or len(new_comment) == 0 or new_comment == current_comment:
                continue

            if (current_comment is not None) and (len(current_comment) > 0):
                description = "Comment [0x%x]: %s\n(YOURS: %s)" % (address, new_comment, current_comment)
            else:
                description = "Comment [0x%x]: %s" % (address, new_comment)

        elif item_type == ItemType.RepeatableComment:
            new_comment = item['comment']
            current_comment = common.get_repeated_comment(address)

            if new_comment is None or len(new_comment) == 0 or new_comment == current_comment:
                continue

            if (current_comment is not None) and (len(current_comment) > 0):
                description = "RComment [0x%x]: %s\n(YOURS: %s)" % (address, new_comment, current_comment)
            else:
                description = "RComment [0x%x]: %s" % (address, new_comment)

        elif item_type == ItemType.AnteriorLines:
            new_lines = item['lines']
            current_lines = get_anterior_lines(address)

            if new_lines is None or len(new_lines) == 0 or new_lines == current_lines:
                continue

            if (current_lines is not None) and (len(current_lines) > 0):
                description = "AntLine [0x%x]: %s\n(YOURS: %s)" % (address,
                                                                   '\n'.join(new_lines),
                                                                   '\n'.join(current_lines))
            else:
                description = "AntLine [0x%x]: %s" % (address, '\n'.join(new_lines))

        elif item_type == ItemType.PosteriorLines:
            new_lines = item['lines']
            current_lines = get_posterior_lines(address)

            if new_lines is None or len(new_lines) == 0 or new_lines == current_lines:
                continue

            if (current_lines is not None) and (len(current_lines) > 0):
                description = "PostLine [0x%x]: %s\n(YOURS: %s)" % (address,
                                                                    '\n'.join(new_lines),
                                                                    '\n'.join(current_lines))
            else:
                description = "PostLine [0x%x]: %s" % (address, '\n'.join(new_lines))
        else:
            print "WHAAAAAT does type %d mean in message %s?" % (item_type, str(item))
            continue

        add_item_to_form(item, description)


def make_items(idb_data):
    # convert the dictionary from unpickling into items
    # for the merge form

    items = []

    for address, new_name in idb_data[NAMES_FIELD].iteritems():
        items.append({'type': ItemType.Name,
                      'address': address,
                      'name': new_name})

    for address, comments_tuple in idb_data[COMMENTS_FIELD].iteritems():
        comment = comments_tuple[0]
        repeated_comment = comments_tuple[1]
        anterior_lines = comments_tuple[2]
        posterior_lines = comments_tuple[3]

        if comment is not None and len(comment) > 0:
            items.append({'type': ItemType.Comment,
                          'address': address,
                          'comment': comment
                          })

        if repeated_comment is not None and len(repeated_comment) > 0:
            items.append({'type': ItemType.RepeatableComment,
                          'address': address,
                          'comment': repeated_comment
                          })
        if anterior_lines is not None and len(anterior_lines) > 0 and len(''.join(anterior_lines)) > 0:
            items.append({'type': ItemType.AnteriorLines,
                          'address': address,
                          'lines': anterior_lines
                          })

        if posterior_lines is not None and len(posterior_lines) > 0 and len(''.join(posterior_lines)) > 0:
            items.append({'type': ItemType.PosteriorLines,
                          'address': address,
                          'lines': posterior_lines
                          })

    items.sort(key=lambda x: x['address'])
    return items


def on_item_list_double_clicked(index):
    row_index = index.row()
    apply_item(row_index)
    idc.Refresh()


def on_go_to_address_button_clicked():
    indices = g_item_list.selectedIndexes()
    if len(indices) != 1:
        return

    index = indices[0].row()
    address = g_item_list_model.item(index).data()['address']
    idc.Jump(address)


def on_apply_button_clicked():
    indices = [index.row() for index in g_item_list.selectedIndexes()]

    removed_rows = 0
    # since every time you apply an update you discard it
    # AND you have to keep the update order you need to
    # track the offset for all indices after the one you just removed
    for i in sorted(indices):
        row_was_removed = apply_item(i - removed_rows)
        if row_was_removed:
            removed_rows += 1

    idc.Refresh()


def on_discard_button_clicked():
    indices = [index.row() for index in g_item_list.selectedIndexes()]
    for i in sorted(indices, reverse=True):
        g_item_list_model.removeRow(i)


def apply_item(row_index):
    """
    Returns True iff row was removed after applying.
    """
    should_remove_row = True
    hooks_enabled_old_value = idb_push.g_hooks_enabled

    try:
        idb_push.g_hooks_enabled = False

        # apply update
        item = g_item_list_model.item(row_index).data()
        item = common.convert_struct_to_utf8(item)
        item_type = item['type']
        address = item['address']

        if item_type == ItemType.Name:
            name = item['name']
            if not common.set_name(address, name):
                print "Failed to name 0x%x as %s" % (address, name)
                should_remove_row = False

        elif item_type == ItemType.Comment:
            comment = item['comment']
            common.set_comment(address, comment)

        elif item_type == ItemType.RepeatableComment:
            comment = item['comment']
            common.set_repeated_comment(address, comment)

        elif item_type == ItemType.AnteriorLines:
            lines = item['lines']
            set_anterior_lines(address, lines)

        elif item_type == ItemType.PosteriorLines:
            lines = item['lines']
            set_posterior_lines(address, lines)
        else:
            print "WHAAAAAT does type %d mean in update %s?" % (item_type, item)
            should_remove_row = False

        if should_remove_row:
            g_item_list_model.removeRow(row_index)

    except:
        traceback.print_exc()
        raise

    finally:
        idb_push.g_hooks_enabled = hooks_enabled_old_value
        return should_remove_row


def unpickle(source_file=None,
             overwrite=False,
             ignore_segment_change=False,
             ignore_md5_mismatch=False,
             visual_merge=True):
    """
    Loads information from the given pickled file.
    """
    if source_file is None:
        source_file = QtWidgets.QFileDialog.getOpenFileName()[0]

    hooks_enabled = idb_push.g_hooks_enabled
    try:
        print "Started unpickling at %s" % (time.ctime())
        idb_push.g_hooks_enabled = False

        with open(source_file, 'rb') as f:
            idb_data = cPickle.load(f)

        # verify MD5
        if idb_data[INPUT_FILE_MD5_FIELD] != idc.GetInputMD5() and not ignore_md5_mismatch:
            print "MD5 mismatch - unpickled file for %s but working on %s" % (
                idb_data[INPUT_FILE_MD5_FIELD], idc.GetInputMD5())
            return

        # check for segment change
        if not ignore_segment_change:
            # using iteritems since iterating on a dictionary returns only the dictionary keys
            if common.get_segments() != idb_data[SEGMENTS]:
                if 1 != idc.AskYN(0, SEGMENT_WARNING % (format_segments(idb_data[SEGMENTS]),
                                                        format_segments(common.get_segments()))):
                    # user replied No or Cancel
                    return

        # apply idb_data (unless overwrite==True, in which case
        # you just overwrite everything)
        if visual_merge and not overwrite:
            # apply non-conflicting updates
            name_conflicts = {}
            comment_conflicts = {}

            set_names(idb_data[NAMES_FIELD], overwrite, name_conflicts)
            set_all_comments(idb_data[COMMENTS_FIELD], overwrite, comment_conflicts)

            conflicts = {NAMES_FIELD: name_conflicts,
                         COMMENTS_FIELD: comment_conflicts}

            if len(name_conflicts) + len(comment_conflicts) == 0:
                # no conflicts need solving
                print "Unpickling complete at %s" % (time.ctime())
                return

            global g_form
            if g_form is not None:
                g_form.Close(idaapi.PluginForm.FORM_SAVE)

            g_form = IDBMergeForm()
            g_form.Show("IDB MERGE")

            populate_form_with_items(make_items(conflicts))

        else:
            set_names(idb_data[NAMES_FIELD], overwrite)
            set_all_comments(idb_data[COMMENTS_FIELD], overwrite)

            idc.Refresh()
            idc.RefreshLists()
            print "Unpickling complete at %s" % (time.ctime())

    except:
        traceback.print_exc()
        raise

    finally:
        idb_push.g_hooks_enabled = hooks_enabled
