import hooks
import psida_common
import idc, ida_struct, ida_nalt
from idb_push_config import *


class UpdateTypes(object):
    (Name, Comment, RepeatableComment, AnteriorLine, PosteriorLine, LookHere, StackVariableRenamed,
     StructMemberCreated, StructMemberRenamed) = range(9)


def get_identifier(update_json):
    update_type = update_json['type']
    address = update_json['address']

    if update_type in [UpdateTypes.AnteriorLine,
                       UpdateTypes.PosteriorLine]:
        return address, update_type, update_json['line_index']

    elif update_type == UpdateTypes.StackVariableRenamed:
        return address, update_type, update_json['offset']

    return address, update_type


def apply_update_to_idb(update):
    """Applies the update from the IDB PUSH window at row_index

    Args:
        update (dict): JSON dictionary containing update data

    Returns:
        tuple (bool, bool):
            Whether applying the change was successful
            Whether the update's UI element should be removed
    """
    should_remove_row = True
    successfully_executed = False

    try:
        hooks.g_hooks_enabled = False
        # apply update

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

        successfully_executed = True
    except:
        if CONFIGURATION['debug']:
            traceback.print_exc()
        pass

    finally:
        hooks.g_hooks_enabled = True

    # assert g_item_list_model.rowCount() == len(g_identifiers_to_updates),\
    #     "ASSERT: different number of items in the list model and the idenfiers-to-updates mapping"
    return successfully_executed, should_remove_row



