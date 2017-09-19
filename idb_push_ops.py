import json
import math

import psida_common

import idc
import ida_struct
import ida_nalt
import ida_bytes

import idb_push_config
reload(idb_push_config)
from idb_push_config import *


class UpdateTypes(object):
    (Name, Comment, RepeatableComment, AnteriorLine, PosteriorLine, LookHere, StackVariableRenamed,
     StructMemberCreated, StructMemberRenamed, StructCreated, MakeData) = range(11)


UpdateTypesNames = ("Name", "Comment", "RComment", "AntLine", "PostLine", "LookHere",
                    "StackVar", "StructMemCreated", "StructMemRenamed", "StructCreated", "MakeData")


class IdbUpdate(object):
    ATTRIBUTES = ['user', 'project', 'address', 'data', 'update_type']

    def __init__(self, **kwargs):
        self.address = None
        self.data = None
        self.update_type = None
        self.user = None
        self.project = None
        self.data_at_address = None

        if 'user' not in kwargs:
            self.user = CONFIGURATION[USER]
        if 'project' not in kwargs:
            self.project = os.path.basename(idc.get_idb_path())

        for attribute_name in self.ATTRIBUTES:
            if self.__getattribute__(attribute_name) is None:
                if attribute_name not in kwargs:
                    raise Exception("ERROR - Ops - Required attribute name %s does not appear in arguments" % attribute_name)
                self.__setattr__(attribute_name, kwargs[attribute_name])

    def to_dict(self):
        attr_dict = {}
        for attribute_name in self.ATTRIBUTES:
            attr_dict[attribute_name] = self.__getattribute__(attribute_name)
        return attr_dict

    def go_to(self):
        """
        Transfers user to the relevant address of the update

        :return: None
        """
        idc.jumpto(self.address)

    def __str__(self):
        """
        :return: (str) A description to appear in UI
        """
        description = "%s [0x%x]: %s" % (UpdateTypesNames[self.update_type],
                                         self.address,
                                         self.data)
        if self.data_at_address:
            description += "\n(YOURS: %s)" % self.data_at_address
        return description

    def get_identifier(self):
        """
        Constructs a unique identifier for the item on the UI element list

        :return: (str) The unique identifier
        """
        return self.address, self.update_type

    def apply(self):
        """
        Applies update to the IDB

        :return: (bool) Whether the update should be removed
        """
        pass

    def has_conflict(self):
        """
        Checks if update has a conflicting data

        :return: (boo) Whether the update has a conflict
        """
        return self.data_at_address is not None


class CommentUpdate(IdbUpdate):
    def __init__(self, **kwargs):
        super(CommentUpdate, self).__init__(**kwargs)

    def apply(self):
        if self.update_type == UpdateTypes.Comment:
            psida_common.set_comment(self.address, self.data)

        elif self.update_type == UpdateTypes.RepeatableComment:
            psida_common.set_repeated_comment(self.address, self.data)

        return True


class NameUpdate(IdbUpdate):
    ATTRIBUTES = ['user', 'project', 'address', 'data', 'update_type', 'is_local']

    def __init__(self, **kwargs):
        self.is_local = None
        super(NameUpdate, self).__init__(**kwargs)

    def apply(self):
        if not psida_common.set_name(self.address, self.data, self.is_local):
            print 'ERROR - NameUpdate - Failed to name 0x%x as %s' % (self.address, self.data)
            return False
        return True


class PostAntLineUpdate(IdbUpdate):
    ATTRIBUTES = ['user', 'project', 'address', 'data', 'update_type', 'line_index']

    def __init__(self, **kwargs):
        self.line_index = None
        super(PostAntLineUpdate, self).__init__(**kwargs)
        if self.update_type == UpdateTypes.AnteriorLine:
            self.base = idc.E_PREV
        else:
            self.base = idc.E_NEXT

    def get_identifier(self):
        return self.address, self.update_type, self.line_index

    def __str__(self):
        """
        :return: (str) A description to appear in UI
        """
        line_num = self.line_index - self.base
        description = "%s [Line: %d] [%d]: %s" % (UpdateTypesNames[self.update_type],
                                                  line_num,
                                                  self.address,
                                                  self.data)
        if self.data_at_address:
            description += "\n(YOURS: %s)" % self.data_at_address
        return description

    def apply(self):
        for i in xrange(self.base, self.line_index):
            line = idc.get_extra_cmt(self.address, i)
            if line is None or len(line) == 0:
                idc.update_extra_cmt(self.address, i, " ")

        idc.update_extra_cmt(self.address, self.line_index, self.data)
        return True


class LookHereUpdate(IdbUpdate):
    def __init__(self, **kwargs):
        super(LookHereUpdate, self).__init__(**kwargs)

    def __str__(self):
        description = "%s: look at 0x%x" % (self.user,
                                            self.address)

        if self.data_at_address:
            description += "(YOUR NAME: %s)" % self.data_at_address
        return description

    def apply(self):
        self.go_to()
        return False


class StackVariableUpdate(IdbUpdate):
    ATTRIBUTES = ['user', 'project', 'address', 'data', 'update_type', 'offset', 'var_size']

    def __init__(self, **kwargs):
        self.func_frame_pointer = None
        self.offset = None
        self.new = None
        self.var_size = None
        super(StackVariableUpdate, self).__init__(**kwargs)

    def __str__(self):
        description = super(StackVariableUpdate, self).__str__()
        if not self.data_at_address:
            description += "\n(At offset: 0x%x)" % self.offset
        return description

    def apply(self):
        func_frame = self.func_frame_pointer
        if self.new:
            ida_struct.add_struc_member(func_frame, self.data, self.offset, 0, ida_nalt.opinfo_t(), self.var_size)
        else:
            ida_struct.set_member_name(func_frame, self.offset, self.data)
        return True


class MakeDataUpdate(IdbUpdate):
    ATTRIBUTES = ['user', 'project', 'address', 'data', 'update_type', 'flags', 'data_type']
    TYPE_TO_SIZE = {
        ida_bytes.FF_BYTE: 1,  # Byte
        ida_bytes.FF_WORD: 2,  # Word
        ida_bytes.FF_DWORD: 4,  # Dword
        ida_bytes.FF_STRLIT: 1,  # Ascii
    }
    TYPE_TO_FUNC = {
        # TODO: Implement other data changes
        ida_bytes.FF_BYTE: ida_bytes.create_byte,
        ida_bytes.FF_WORD: ida_bytes.create_word,
        ida_bytes.FF_DWORD: ida_bytes.create_dword,
        ida_bytes.FF_STRLIT: ida_bytes.create_strlit
    }
    TYPE_TO_NAME = {
        ida_bytes.FF_BYTE: "Byte",
        ida_bytes.FF_WORD: "Word",
        ida_bytes.FF_DWORD: "Dword",
        ida_bytes.FF_STRLIT: "String Byte"
    }

    def __init__(self, **kwargs):
        self.flags = None
        self.data_type = None
        super(MakeDataUpdate, self).__init__(**kwargs)

    def __str__(self):
        num = self._get_num_of_elements()
        data = str(num) + " " + self.TYPE_TO_NAME[self.data_type]
        if num > 1:
            data += "s"
        description = "%s [0x%x]: %s" % (UpdateTypesNames[self.update_type],
                                         self.address,
                                         data)
        if self.data_at_address:
            description += "\n(YOURS: %s)" % self.data_at_address
        return description

    def apply(self):
        # TODO: Throw this in common
        ida_bytes.del_items(self.address, ida_bytes.DELIT_SIMPLE, self.data)

        if self.data_type == ida_bytes.FF_STRLIT:
            self.TYPE_TO_FUNC[self.data_type](self.address, self.data, ida_nalt.STRTYPE_TERMCHR)
            return True
        elif self.data_type in self.TYPE_TO_FUNC.keys():
            self.TYPE_TO_FUNC[self.data_type](self.address, self.data)
            return True
        else:
            raise Exception("ERORR - MakeDataUpdate - Apply - Unimplemented data update")

    def get_conflict(self):
        """

        :return: None if there's no conflict, empty string if there's no change, data if there's a change.
        """
        # TODO: Fill docstring, plus, make the function return 0,1,2 and save the current data by itself.
        code_address = self._has_code()
        if code_address:
            return 'Code: 0x%x' % code_address

        num_of_elements = self._get_num_of_elements()

        data_undefined = True
        for i in xrange(self.data):
            ea_flags = ida_bytes.get_full_flags(self.address + i)
            if ea_flags & 0x400:  # Data defined
                data_undefined = False
        if data_undefined:
            return None  # No conflict

        # Iterate over all local data, and check if there's any conflict with the type
        conflict = ''
        for i in xrange(num_of_elements):
            current_address = self.address + (i * self.TYPE_TO_SIZE[self.data_type])
            current_address = ida_bytes.get_item_head(current_address)
            ea_flags = ida_bytes.get_full_flags(current_address)
            if not ida_bytes.is_data(ea_flags):
                conflict += 'unknown at 0x%x\n' % current_address
                continue
            current_data_type = ea_flags & ida_bytes.DT_TYPE
            if self.data_type != current_data_type:  # Different data
                conflict += '%s at 0x%x\n' % (self.TYPE_TO_NAME[current_data_type], current_address)
        if conflict:
            return conflict

        # TODO: Deal with the case it's just multiple type definitions in the area?
        return ''  # No difference

    def _get_num_of_elements(self):
        return self.data / self.TYPE_TO_SIZE[self.data_type]

    def _has_code(self):
        for i in xrange(self.data):
            maybe_start_of_item = ida_bytes.get_item_head(self.address + i)
            if ida_bytes.is_code(ida_bytes.get_full_flags(maybe_start_of_item)):
                return self.address + i
        return None


class StructCreatedUpdate(IdbUpdate):
    pass  # Not implemented yet


class StructRenamedUpdate(IdbUpdate):
    pass  # Not implemented yet


class StructMemCreatedUpdate(IdbUpdate):
    pass  # Not implemented yet


class StructMemRenamedUpdate(IdbUpdate):
    pass  # Not implemented yet


TYPE_TO_CLASS = {
    UpdateTypes.Name: NameUpdate,
    UpdateTypes.Comment: CommentUpdate,
    UpdateTypes.RepeatableComment: CommentUpdate,
    UpdateTypes.AnteriorLine: PostAntLineUpdate,
    UpdateTypes.PosteriorLine: PostAntLineUpdate,
    UpdateTypes.LookHere: LookHereUpdate,
    UpdateTypes.StackVariableRenamed: StackVariableUpdate,
    UpdateTypes.StructMemberCreated: StructMemCreatedUpdate,
    UpdateTypes.StructMemberRenamed: StructMemRenamedUpdate,
    UpdateTypes.StructCreated: StructCreatedUpdate,
    UpdateTypes.MakeData: MakeDataUpdate
}


def from_json(json_message):
    message = json.loads(json_message)
    if message is None or len(message) == 0 or type(message) != dict:
        return

    message = psida_common.convert_struct_to_utf8(message)

    if 'user' not in message or message['user'] == CONFIGURATION[USER]:
        # don't receive your own updates
        return
    if 'project' not in message or message['project'] != os.path.basename(idc.get_idb_path()):
        # don't receive updates for other projects
        return

    return TYPE_TO_CLASS[message['update_type']](**message)
