import itertools
import string
import re

__author__ = 'Alexei'

# noinspection PyBroadException
try:
    import idc
    import idautils
    import ida_name
    import ida_funcs
    import ida_bytes
except ImportError:
    idc = None
    idautils = None
    ida_name = None
    ida_funcs = None
    ida_bytes = None

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
    return idc.first_func_chunk(address) == address


def get_comment(address):
    comment = ida_bytes.get_cmt(address, 0)
    if comment is None or 0 == len(comment):
        return None
    return comment


def set_comment(address, comment):
    assert type(comment) == str

    # Always succeeds
    ida_bytes.set_cmt(address, comment, 0)


def get_repeated_comment(address):
    if is_function_start(address):
        pfn = ida_funcs.get_func(address)
        repeated_comment = ida_funcs.get_func_cmt(pfn, 1)
    else:
        repeated_comment = ida_bytes.get_cmt(address, 1)

    if repeated_comment is None or len(repeated_comment) == 0:
        return None
    return repeated_comment


def set_repeated_comment(address, repeated_comment):
    assert type(repeated_comment) == str
    if is_function_start(address):
        pfn = ida_funcs.get_func(address)
        ida_funcs.set_func_cmt(pfn, repeated_comment, 1)
    else:
        ida_bytes.set_cmt(address, repeated_comment, 1)


def get_non_default_name(address, is_local=False):
    flags = 0
    if is_local:
        flags = flags | idc.GN_LOCAL
    name = idc.get_name(address, flags)
    if name is not None and len(name) > 0 and not is_default_name(name):
        return name
    return None


def set_name(address, new_name, local):
    assert type(new_name) == str

    is_hidden = idc.is_tail(idc.get_full_flags(address))

    if is_hidden:
        print "0x%x: can't rename byte as '%s' because the address is not visible" % (address, new_name)
        return False

    flags = idc.SN_CHECK | idc.SN_NOWARN
    if local:
        flags = flags | idc.SN_LOCAL

    ret = ida_name.set_name(address, new_name, flags)

    if ret is False:
        print "0x%x: can't rename byte as '%s' because the name is already used at 0x%x" % (address,
                                                                                            new_name,
                                                                                            current_name_location)
    return ret
