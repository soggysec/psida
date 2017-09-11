import pprint

import idc
import idaapi
import ida_frame
import ida_struct

import psida_common
import zmq_primitives
import idb_push_ops
from idb_push_config import *
if CONFIGURATION[DEBUG]:
    reload(psida_common)
    reload(zmq_primitives)
    reload(idb_push_ops)

CONTEXT_MENU_ACTION_NAME = 'idb_push:send_address'

g_hooks_enabled = False
g_zmq_socket = None
g_ui_hooks = None


def send_push_update(update):
    zmq_primitives.zmq_send_json(g_zmq_socket,
                                 update.to_dict())


class IDPHook(idaapi.IDP_Hooks):
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def renamed(self, ea, new_name, local_name):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - RenameIDPHook.renamed(ea = 0x%x, new_name = %s, local_name = %r)' % (
                ea, new_name, local_name)

        if ida_struct.is_member_id(ea):
            # Change is either a built-in struct of a frame pointer, or some address
            # starting with 0xFF00 that happens to be a member address.
            print 'INFO - Hooks - RenameIDPHook - Skipping a possible stack variable/built-in struct change'
            return idaapi.IDP_Hooks.renamed(self, ea, new_name, local_name)

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

        return idaapi.IDP_Hooks.renamed(self, ea, new_name, local_name)


class IDBHook(idaapi.IDB_Hooks):
    def __init__(self):
        idaapi.IDB_Hooks.__init__(self)

    def cmt_changed(self, ea, is_repeatable):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - CommentIDBHook.cmt_changed(arg0 = 0x%x, is_repeatable = %s)' % (ea, is_repeatable)

        if is_repeatable:
            data = psida_common.get_repeated_comment(ea)
            comment_update = idb_push_ops.CommentUpdate(
                update_type=idb_push_ops.UpdateTypes.RepeatableComment,
                address=ea,
                data=psida_common.get_repeated_comment(ea))
        else:
            data = psida_common.get_comment(ea)
            comment_update = idb_push_ops.CommentUpdate(
                update_type=idb_push_ops.UpdateTypes.Comment,
                address=ea,
                data=psida_common.get_comment(ea))

        if g_hooks_enabled and (data is not None) and (len(data) > 0):
            send_push_update(comment_update)

        return idaapi.IDB_Hooks.cmt_changed(self, ea, is_repeatable)

    def area_cmt_changed(self, areas, area, comment, is_repeatable):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - CommentIDBHook.area_cmt_changed(area_start = 0x%x, comment = %s)' % (
                area.startEA, comment)

        ea = area.startEA
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

        return idaapi.IDB_Hooks.area_cmt_changed(self, areas, area, comment, is_repeatable)

    def extra_cmt_changed(self, ea, line_idx, cmt):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - CommentIDBHook.extra_cmt_changed(ea = 0x%x, line_idx = %d, cmt = %s)' % (
                ea, line_idx, cmt)

        if idaapi.E_PREV <= line_idx < idaapi.E_NEXT:
            line_index = line_idx - idaapi.E_PREV
            line_update = idb_push_ops.PostAntLineUpdate(
                update_type=idb_push_ops.UpdateTypes.AnteriorLine,
                address=ea,
                data=cmt,
                line_index=line_index)
        elif line_idx >= idaapi.E_NEXT:
            line_index = line_idx - idaapi.E_NEXT
            line_update = idb_push_ops.PostAntLineUpdate(
                update_type=idb_push_ops.UpdateTypes.PosteriorLine,
                address=ea,
                data=cmt,
                line_index=line_index)
        else:
            if CONFIGURATION[DEBUG]:
                print 'DEBUG - Hooks - CommentIDBHook.extra_cmt_changed - unexpected line_idx, continuing...'
            return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)

        if g_hooks_enabled and (cmt is not None) and (len(cmt) > 0):  # TODO(alexei): ????
            send_push_update(line_update)

        return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)

    def struc_member_created(self, sptr, mptr):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - StructIDBHook.struc_member_created(sptr = %s, mptr = %s)' % (
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
            update = idb_push_ops.StructMemCreatedUpdate(
                    update_type=idb_push_ops.UpdateTypes.StructMemberCreated,
                    address=ida_frame.get_func_by_frame(sptr.id),
                    data=data,
                    offset=mptr.soff,
                    var_size=mptr.eoff - mptr.soff)

        if g_hooks_enabled and (data is not None) and (len(data) > 0):
            send_push_update(update)

        return idaapi.IDB_Hooks.struc_member_created(self, sptr, mptr)

    def struc_member_renamed(self, sptr, mptr):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - StructIDBHook.struc_member_renamed(sptr = %s, mptr = %s)' % (
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
            update = idb_push_ops.StructMemRenamedUpdate(
                update_type=idb_push_ops.UpdateTypes.StructMemberRenamed,
                address=ida_frame.get_func_by_frame(sptr.id),
                data=data,
                offset=mptr.soff,
                var_size=mptr.eoff - mptr.soff)

        if g_hooks_enabled and (data is not None) and (len(data) > 0):
            send_push_update(update)

        return idaapi.IDB_Hooks.struc_member_renamed(self, sptr, mptr)


class SendPointerFromContextMenu(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        look_here_update = idb_push_ops.LookHereUpdate(
            update_type=idb_push_ops.UpdateTypes.LookHere,
            address=idc.ScreenEA())
        send_push_update(look_here_update)
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
