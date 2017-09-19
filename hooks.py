import pprint

import idc
import idaapi
import ida_frame
import ida_struct

import psida_common
import zmq_primitives
import idb_push_ops
import idb_push_config
reload(idb_push_config)
from idb_push_config import *
# Reload hack for debug sessions
if CONFIGURATION[DEBUG]:
    reload(psida_common)
    reload(zmq_primitives)
    reload(idb_push_ops)

CONTEXT_MENU_ACTION_NAME = 'idb_push:send_address'

g_hooks_enabled = False  # Holds the current state of the programmatic hooks
g_zmq_socket = None  # Holds the zmq socket instance to be used on outgoing updates
g_ui_hooks = None  # Holds the UI hooks currently installed (if any)


def send_push_update(update):
    """
    Sends an update to the zmq server using the global socket. (Assumes it's open.)

    :param update: (IdbUpdate) The update to be sent to server.
    :return: None
    """
    zmq_primitives.zmq_send_json(g_zmq_socket,
                                 update.to_dict())


class IDBHook(idaapi.IDB_Hooks):
    """
    A class used to override hooks in IDB_Hooks module:
        cmt_changed - Invoked on every comment or repeatable comment change in the IDB
        area_cmt_changed - # TODO
        extra_cmt_changed - Invoked on every anterior or posterior comment change in the IDB
        struc_member_created - Invoked on every struct member creation (Including new stack variables)
        struc_member_renamed - Invoked on every struct member rename (Including stack variables)
    A class used to override hooks in IDP_Hooks module:
        renamed - Invoked on every name change in the IDB - address, function, struct, stack.
    """
    def __init__(self):
        idaapi.IDB_Hooks.__init__(self)

    def renamed(self, ea, new_name, local_name):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - IDBHook.renamed(ea = 0x%x, new_name = %s, local_name = %r)' % (
                ea, new_name, local_name)

        if ida_struct.is_member_id(ea) or ida_struct.get_struc(ea):
            # Change is either a built-in struct of a frame pointer, or some address
            # starting with 0xFF00 that happens to be a member address.

            print 'INFO - Hooks - IDBHook.Renamed - Skipping a possible stack variable/built-in struct change'
            return idaapi.IDB_Hooks.renamed(self, ea, new_name, local_name)

        if (g_hooks_enabled and
                (new_name is not None) and
                (len(new_name) > 0) and
                (not psida_common.is_default_name(new_name))):
            name_update = idb_push_ops.NameUpdate(
                update_type=idb_push_ops.UpdateTypes.Name,
                address=ea,
                data=new_name,
                is_local=local_name)
            send_push_update(name_update)

        return idaapi.IDB_Hooks.renamed(self, ea, new_name, local_name)

    def make_data(self, ea, flags, tid, len):
        # TID changes when data is changed using alt+Q
        # Flags are:
        # & 0xF00 - 0x400 for Data,
        # & 0xF0000000 - 0x0 = Byte, 0x10000000 = Word, 0x20000000 = Dword, 0x50000000 = ASCII, 0xB0000000 = Alignment
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - IDBHook.make_data(ea = 0x%x, flags=0x%x, tid=0x%x, len=%d)' % (ea, flags, tid, len)

        if g_hooks_enabled:
            data_update = idb_push_ops.MakeDataUpdate(
                update_type=idb_push_ops.UpdateTypes.MakeData,
                address=ea,
                data=len,
                flags=flags,
                data_type=flags & 0xF0000000
            )
            send_push_update(data_update)

        return idaapi.IDB_Hooks.make_data(self, ea, flags, tid, len)

    def make_code(self, ea, size):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - IDBHook.make_code(ea = 0x%x, size=%d)' % (ea, size)

        return idaapi.IDB_Hooks.make_code(self, ea, size)

    def cmt_changed(self, ea, is_repeatable):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - IDBHook.cmt_changed(arg0 = 0x%x, is_repeatable = %s)' % (ea, is_repeatable)

        if is_repeatable:
            data = psida_common.get_repeated_comment(ea)
            comment_update = idb_push_ops.CommentUpdate(
                update_type=idb_push_ops.UpdateTypes.RepeatableComment,
                address=ea,
                data=data)
        else:
            data = psida_common.get_comment(ea)
            comment_update = idb_push_ops.CommentUpdate(
                update_type=idb_push_ops.UpdateTypes.Comment,
                address=ea,
                data=data)

        if g_hooks_enabled and (data is not None) and (len(data) > 0):
            send_push_update(comment_update)

        return idaapi.IDB_Hooks.cmt_changed(self, ea, is_repeatable)

    def range_cmt_changed(self, areas, cmt_range, comment, is_repeatable):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - IDBHook.range_cmt_changed(area_start = 0x%x, comment = %s)' % (
                cmt_range.start_ea, comment)

        ea = cmt_range.start_ea
        if is_repeatable:
            data = psida_common.get_repeated_comment(ea)
            comment_update = idb_push_ops.CommentUpdate(
                update_type=idb_push_ops.UpdateTypes.RepeatableComment,
                address=ea,
                data=data)
        else:
            data = psida_common.get_comment(ea)
            comment_update = idb_push_ops.CommentUpdate(
                update_type=idb_push_ops.UpdateTypes.Comment,
                address=ea,
                data=data)

        if g_hooks_enabled and (data is not None) and (len(data) > 0):
            send_push_update(comment_update)

        return idaapi.IDB_Hooks.range_cmt_changed(self, areas, cmt_range, comment, is_repeatable)

    def extra_cmt_changed(self, ea, line_idx, cmt):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - IDBHook.extra_cmt_changed(ea = 0x%x, line_idx = %d, cmt = %s)' % (
                ea, line_idx, cmt)

        if idaapi.E_PREV <= line_idx < idaapi.E_NEXT:
            line_update = idb_push_ops.PostAntLineUpdate(
                update_type=idb_push_ops.UpdateTypes.AnteriorLine,
                address=ea,
                data=cmt,
                line_index=line_idx)
        elif line_idx >= idaapi.E_NEXT:
            line_update = idb_push_ops.PostAntLineUpdate(
                update_type=idb_push_ops.UpdateTypes.PosteriorLine,
                address=ea,
                data=cmt,
                line_index=line_idx)
        else:
            if CONFIGURATION[DEBUG]:
                print 'DEBUG - Hooks - IDBHook.extra_cmt_changed - unexpected line_idx, continuing...'
            return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)

        if g_hooks_enabled and (cmt is not None) and (len(cmt) > 0) and (cmt != ' '):
            send_push_update(line_update)

        return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)

    def struc_member_created(self, sptr, mptr):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - IDBHook.struc_member_created(sptr = %s, mptr = %s)' % (
                pprint.pformat(sptr), pprint.pformat(mptr))

        data = ida_struct.get_member_name(mptr.id)
        if sptr.props & 0x40:  # Struct changed is a frame pointer
            update = idb_push_ops.StackVariableUpdate(
                    update_type=idb_push_ops.UpdateTypes.StackVariableRenamed,
                    address=ida_frame.get_func_by_frame(sptr.id),
                    data=data,
                    offset=mptr.soff,
                    var_size=mptr.eoff - mptr.soff)
        else:
            return idaapi.IDB_Hooks.struc_member_created(self, sptr, mptr)

        if g_hooks_enabled and (data is not None) and (len(data) > 0):
            send_push_update(update)

        return idaapi.IDB_Hooks.struc_member_created(self, sptr, mptr)

    def struc_member_renamed(self, sptr, mptr):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - IDBHook.struc_member_renamed(sptr = %s, mptr = %s)' % (
                pprint.pformat(sptr), pprint.pformat(mptr))

        data = ida_struct.get_member_name(mptr.id)
        if sptr.props & 0x40:  # Struct changed is a frame pointer
            update = idb_push_ops.StackVariableUpdate(
                update_type=idb_push_ops.UpdateTypes.StackVariableRenamed,
                address=ida_frame.get_func_by_frame(sptr.id),
                data=data,
                offset=mptr.soff,
                var_size=mptr.eoff - mptr.soff)
        else:
            return idaapi.IDB_Hooks.struc_member_created(self, sptr, mptr)

        if g_hooks_enabled and (data is not None) and (len(data) > 0):
            send_push_update(update)

        return idaapi.IDB_Hooks.struc_member_renamed(self, sptr, mptr)

    def struc_expanded(self, sptr):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - IDBHook.struc_expanded(sptr = %s)' % sptr

        return idaapi.IDB_Hooks.struc_expanded(self, sptr)

    def struc_member_changed(self, sptr, mptr):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - IDBHook.struc_member_changed(sptr = %s, mptr = %s)' % (sptr, mptr)

        return idaapi.IDB_Hooks.struc_member_changed(self, sptr, mptr)

    def struc_created(self, struc_id):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - IDBHook.struc_created(struc_id = 0x%x)' % struc_id

        return idaapi.IDB_Hooks.struc_created(self, struc_id)

    def struc_renamed(self, sptr):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - IDBHook.struc_renamed(sptr = %s)' % sptr

        return idaapi.IDB_Hooks.struc_renamed(self, sptr)

    def changing_op_type(self, ea, n, opinfo):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - IDBHook.changing_op_type(ea = 0x%x, n=%d, opinfo=%s)' % (ea, n, opinfo)

        return idaapi.IDB_Hooks.changing_op_type(self, ea, n, opinfo)


class SendPointerFromContextMenu(idaapi.action_handler_t):
    """
    The UI hook to be installed on the context menu.
    Sends the current address as an update
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        look_here_update = idb_push_ops.LookHereUpdate(
            update_type=idb_push_ops.UpdateTypes.LookHere,
            address=idc.ScreenEA())
        send_push_update(look_here_update)
        return 1

    def update(self, ctx):

        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.form_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_WIDGET


class IDBPushUIHooks(idaapi.UI_Hooks):
    """
    Helper class to attack context menu action only on disasm tab.
    """
    def finish_populating_tform_popup(self, form, popup):
        if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, CONTEXT_MENU_ACTION_NAME, None)


def install_ui_hooks():
    """
    Registers the context menu's send address action
    """
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
    """
    Deregisters the context menu's send address action
    """
    idaapi.unregister_action(CONTEXT_MENU_ACTION_NAME)

    global g_ui_hooks
    if g_ui_hooks is not None:
        g_ui_hooks.unhook()
        g_ui_hooks = None
