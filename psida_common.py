import itertools
import string
import re

__author__ = 'Alexei'

# noinspection PyBroadException
try:
    import idc
    import idautils
except:
    idc = None
    idautils = None

VALID_CHARACTERS = string.printable[:-6]


# replacement for xrange for long ints
def my_xrange(*args):
    """
    my_xrange(end)
    my_xrange(start, end)
    my_xrange(start, end, step)
    """
    if len(args) not in [1, 2, 3]:
        raise Exception("my_xrange takes one, two or three arguments")
    if len(args) == 1:
        start = 0
        end = args[0]
        step = 1
    elif len(args) == 2:
        start = args[0]
        end = args[1]
        step = 1
    else:
        # len(args) == 3:
        start = args[0]
        end = args[1]
        step = args[2]
    return iter(itertools.count(start, step).next, end)


DEFAULT_NAME_PREFIXES = ['loc_', 'locret_', 'sub_', 'var_', 'unk_', 'seg_', 'byte_', 'word_', 'dword_', 'off_']
DEFAULT_NAME_REGEX = re.compile('|'.join('(^%s.*)' % p for p in DEFAULT_NAME_PREFIXES))


def is_default_name(name):
    return DEFAULT_NAME_REGEX.match(name) is not None


def sanitize_string(s, default_char='_'):
    s = [c for c in s]
    for i in xrange(len(s)):
        if s[i] not in VALID_CHARACTERS:
            s[i] = default_char
    return ''.join(s)


def convert_struct_to_utf8(struct):
    """
    Converts any composition of primitive types (lists, tuples and dictionaries)
    and (recursively) their contents into UTF-8.
    """
    if isinstance(struct, dict):
        return {convert_struct_to_utf8(key): convert_struct_to_utf8(value) for key, value in struct.iteritems()}
    elif isinstance(struct, list):
        return [convert_struct_to_utf8(element) for element in struct]
    elif isinstance(struct, tuple):
        return tuple([convert_struct_to_utf8(element) for element in struct])
    elif isinstance(struct, set):
        return set([convert_struct_to_utf8(element) for element in struct])
    elif isinstance(struct, unicode):
        return struct.encode('utf-8')
    else:
        return struct


def get_segments():
    """
    Returns a set of  of (segment name, segment start, segment end).
    The end is exclusive - last byte of segment is one byte before.
    """
    segments = set()

    segment_start = idc.FirstSeg()
    while segment_start != idc.BADADDR:
        segment_name = idc.SegName(segment_start)
        segment_end = idc.SegEnd(segment_start)

        segments.add((segment_name, segment_start, segment_end))

        segment_start = idc.NextSeg(segment_start)

    return segments


def is_function_start(address):
    return idc.GetFunctionAttr(address, idc.FUNCATTR_START) == address


def get_comment(address):
    comment = idc.Comment(address)
    if comment is None or 0 == len(comment):
        return None
    return comment


def set_comment(address, comment):
    assert type(comment) == str

    # Always succeeds
    idc.MakeComm(address, comment)


def get_repeated_comment(address):
    if is_function_start(address):
        repeated_comment = idc.GetFunctionCmt(address, 1)
    else:
        repeated_comment = idc.RptCmt(address)

    if repeated_comment is None or len(repeated_comment) == 0:
        return None
    return repeated_comment


def set_repeated_comment(address, repeated_comment):
    assert type(repeated_comment) == str
    if is_function_start(address):
        idc.SetFunctionCmt(address, repeated_comment, 1)
    else:
        idc.MakeRptCmt(address, repeated_comment)


def get_non_default_name(address):
    name = idc.NameEx(address, address)
    if name is not None and len(name) > 0 and not is_default_name(name):
        return name
    return None


def set_name(address, new_name, local):
    assert type(new_name) == str

    if local:
        # Check if this name exists somewhere
        current_name_location = idc.LocByNameEx(address, new_name)
        if current_name_location != idc.BADADDR:
            # Check if it appears in the same function
            if idc.GetFunctionName(address) == idc.GetFunctionName(current_name_location):
                print "0x%x: can't rename byte as '%s' because the name is already used at 0x%x, locally" % (address,
                                                                                            new_name,
                                                                                            current_name_location)
                return False
        return idc.MakeNameEx(address, new_name, idc.SN_LOCAL)
        
    # if the name exists elsewhere you get an annoying popup,
    # so first check that this isn't the case
    current_name_location = idc.LocByName(new_name)
    if current_name_location != idc.BADADDR:
        print "0x%x: can't rename byte as '%s' because the name is already used at 0x%x" % (address,
                                                                                            new_name,
                                                                                            current_name_location)
        return False

    return idc.MakeName(address, new_name)