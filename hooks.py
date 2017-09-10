import idaapi, ida_struct, idc, ida_frame
from idb_push_config import *
import psida_common
import zmq_primitives
from idb_push_ops import *
import pprint

CONTEXT_MENU_ACTION_NAME = 'idb_push:send_address'

g_hooks_enabled = False
g_zmq_socket = None
g_ui_hooks = None


def send_push_update(json_message):
    if 'user' not in json_message:
        json_message['user'] = CONFIGURATION[USER]
    if 'project' not in json_message:
        json_message['project'] = os.path.basename(idc.GetIdbPath())

    zmq_primitives.zmq_send_json(g_zmq_socket,
                                 json_message)


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
            send_push_update({'type': UpdateTypes.Name,
                              'address': ea,
                              'name': new_name,
                              'local_name': local_name})

        return idaapi.IDP_Hooks.renamed(self, ea, new_name, local_name)


class IDBHook(idaapi.IDB_Hooks):
    def __init__(self):
        idaapi.IDB_Hooks.__init__(self)

    def cmt_changed(self, ea, is_repeatable):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - CommentIDBHook.cmt_changed(arg0 = 0x%x, is_repeatable = %s)' % (ea, is_repeatable)

        message = {'address': ea}

        if is_repeatable:
            message['type'] = UpdateTypes.RepeatableComment
            message['comment'] = psida_common.get_repeated_comment(ea)
        else:
            message['type'] = UpdateTypes.Comment
            message['comment'] = psida_common.get_comment(ea)

        if g_hooks_enabled and (message['comment'] is not None) and (len(message['comment']) > 0):
            send_push_update(message)

        return idaapi.IDB_Hooks.cmt_changed(self, ea, is_repeatable)

    def area_cmt_changed(self, areas, area, comment, is_repeatable):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - CommentIDBHook.area_cmt_changed(area_start = 0x%x, comment = %s)' % (
                area.startEA, comment)

        ea = area.startEA
        message = {'address': ea}

        if is_repeatable:
            message['type'] = UpdateTypes.RepeatableComment
            message['comment'] = psida_common.get_repeated_comment(ea)
        else:
            message['type'] = UpdateTypes.Comment
            message['comment'] = psida_common.get_comment(ea)

        if g_hooks_enabled and (message['comment'] is not None) and (len(message['comment']) > 0):
            send_push_update(message)

        return idaapi.IDB_Hooks.area_cmt_changed(self, areas, area, comment, is_repeatable)

    def extra_cmt_changed(self, ea, line_idx, cmt):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - CommentIDBHook.extra_cmt_changed(ea = 0x%x, line_idx = %d, cmt = %s)' % (
                ea, line_idx, cmt)

        message = {'address': ea, 'line': cmt}

        if idaapi.E_PREV <= line_idx < idaapi.E_NEXT:
            message['type'] = UpdateTypes.AnteriorLine
            message['line_index'] = line_idx - idaapi.E_PREV
        elif line_idx >= idaapi.E_NEXT:
            message['type'] = UpdateTypes.PosteriorLine
            message['line_index'] = line_idx - idaapi.E_NEXT
        else:
            if CONFIGURATION[DEBUG]:
                print 'DEBUG - Hooks - CommentIDBHook.extra_cmt_changed - unexpected line_idx, continuing...'
            return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)

        if g_hooks_enabled and (message['line'] is not None) and (len(message['line']) > 0):
            send_push_update(message)

        return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)

    def struc_member_created(self, sptr, mptr):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - StructIDBHook.struc_member_created(sptr = %s, mptr = %s)' % (
                pprint.pformat(sptr), pprint.pformat(mptr))

        message = {'type': UpdateTypes.StructMemberCreated,
                   'name': ida_struct.get_member_name(mptr.id),
                   'address': ida_frame.get_func_by_frame(sptr.id),
                   'offset': mptr.soff,
                   'var_size': mptr.eoff - mptr.soff}

        if sptr.props & 0x40:  # Struct changed is a frame pointer
            message['type'] = UpdateTypes.StackVariableRenamed

        if g_hooks_enabled and (message['name'] is not None) and (len(message['name']) > 0):
            send_push_update(message)

        return idaapi.IDB_Hooks.struc_member_created(self, sptr, mptr)

    def struc_member_renamed(self, sptr, mptr):
        if CONFIGURATION[DEBUG]:
            print 'DEBUG - Hooks - StructIDBHook.struc_member_renamed(sptr = %s, mptr = %s)' % (
                pprint.pformat(sptr), pprint.pformat(mptr))

        message = {'type': UpdateTypes.StructMemberRenamed,
                   'name': ida_struct.get_member_name(mptr.id),
                   'address': ida_frame.get_func_by_frame(sptr.id),
                   'offset': mptr.soff,
                   'var_size': mptr.eoff - mptr.soff}

        if sptr.props & 0x40:  # Struct changed is a frame pointer
            message['type'] = UpdateTypes.StackVariableRenamed

        if g_hooks_enabled and (message['name'] is not None) and (len(message['name']) > 0):
            send_push_update(message)

        return idaapi.IDB_Hooks.struc_member_renamed(self, sptr, mptr)


class SendPointerFromContextMenu(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        send_push_update({'type': UpdateTypes.LookHere,
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
