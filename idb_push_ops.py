import json

import psida_common

import idc
import ida_struct
import ida_nalt

from idb_push_config import *


class UpdateTypes(object):
    (Name, Comment, RepeatableComment, AnteriorLine, PosteriorLine, LookHere, StackVariableRenamed,
     StructMemberCreated, StructMemberRenamed) = range(9)

UpdateTypesNames = ("Name", "Comment", "RComment", "AntLine", "PostLine", "LookHere",
                    "StackVar", "StructMemCreated", "StructMemRenamed")

# TODO: Make any json field constant


class IdbUpdate(object):
    ATTRIBUTES = ['user', 'project', 'address', 'data', 'update_type']

    def __init__(self, **kwargs):
        self.address = None
        self.data = None
        self.update_type = None
        self.user = None
        self.project = None

        self.data_at_address = None

        for attribute_name in kwargs:
            self.__setattr__(attribute_name, kwargs[attribute_name])

        if 'user' not in kwargs:
            self.user = CONFIGURATION[USER]
        if 'project' not in kwargs:
            self.project = os.path.basename(idc.GetIdbPath())

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
        idc.Jump(self.address)

    def __str__(self, data_at_address=None):
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
    def __init__(self, **kwargs):
        self.ATTRIBUTES.append('is_local')
        self.is_local = None
        super(NameUpdate, self).__init__(**kwargs)

    def apply(self):
        if not psida_common.set_name(self.address, self.data, self.is_local):
            print 'ERROR - NameUpdate - Failed to name 0x%x as %s' % (self.address, self.data)
            return False
        return True


class PostAntLineUpdate(IdbUpdate):
    def __init__(self, **kwargs):
        self.ATTRIBUTES.append('line_index')
        self.line_index = None
        super(PostAntLineUpdate, self).__init__(**kwargs)

    def get_identifier(self):
        return self.address, self.update_type, self.line_index

    def __str__(self, data_at_address=None):
        """
        :return: (str) A description to appear in UI
        """
        description = "%s [0x%x] [%d]: %s" % (UpdateTypesNames[self.update_type],
                                              self.line_index,
                                              self.address,
                                              self.data)
        if data_at_address:
            description += "\n(YOURS: %s)" % data_at_address
        return description

    def apply(self):
        line_index = self.line_index
        if self.update_type == UpdateTypes.AnteriorLine:
            # in order for line i to be displayed all lines before i
            # must be non-empty
            for i in xrange(0, line_index):
                line = idc.LineA(self.address, i)
                if line is None or len(line) == 0:
                    idc.ExtLinA(self.address, i, " ")

            idc.ExtLinA(self.address, line_index, self.data)

        elif self.update_type == UpdateTypes.PosteriorLine:
            # in order for line i to be displayed all lines before i
            # must be non-empty
            for i in xrange(0, line_index):
                line = idc.LineB(self.address, i)
                if line is None or len(line) == 0:
                    idc.ExtLinB(self.address, i, ' ')

            idc.ExtLinB(self.address, line_index, self.data)
        return True


class LookHereUpdate(IdbUpdate):
    def __init__(self, **kwargs):
        super(LookHereUpdate, self).__init__(**kwargs)

    def __str__(self, data_at_address=None):
        description = "%s: look at 0x%x" % (self.user,
                                            self.address)

        if data_at_address:
            description += "(YOUR NAME: %s)" % data_at_address
        return description

    def apply(self):
        self.go_to()
        return False


class StackVariableUpdate(IdbUpdate):
    def __init__(self, **kwargs):
        self.ATTRIBUTES.append('func_frame_pointer')
        self.ATTRIBUTES.append('offset')
        self.ATTRIBUTES.append('new')
        self.ATTRIBUTES.append('var_size')
        self.func_frame_pointer = None
        self.offset = None
        self.new = None
        self.var_size = None
        super(StackVariableUpdate, self).__init__(**kwargs)

    def __str__(self, data_at_address=None):
        description = super(StackVariableUpdate, self).__str__(data_at_address)
        if not data_at_address:
            description += "\n(At offset: 0x%x)" % self.offset
        return description

    def apply(self):
        func_frame = self.func_frame_pointer
        if self.new:
            ida_struct.add_struc_member(func_frame, self.data, self.offset, 0, ida_nalt.opinfo_t(), self.data.var_size)
        else:
            ida_struct.set_member_name(func_frame, self.offset, self.data)
        return True


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
    UpdateTypes.StructMemberRenamed: StructMemRenamedUpdate
}


def from_json(json_message):
    message = json.loads(json_message)
    if message is None or len(message) == 0 or type(message) != dict:
        return

    message = psida_common.convert_struct_to_utf8(message)

    if 'user' not in message or message['user'] == CONFIGURATION[USER]:
        # don't receive your own updates
        return
    if 'project' not in message or message['project'] != os.path.basename(idc.GetIdbPath()):
        # don't receive updates for other projects
        return

    return TYPE_TO_CLASS[message['update_type']](**message)
