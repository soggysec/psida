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


def convert_struct_to_ascii(struct):
    if isinstance(struct, dict):
        return {convert_struct_to_ascii(key): convert_struct_to_ascii(value) for key, value in struct.iteritems()}
    elif isinstance(struct, list):
        return [convert_struct_to_ascii(element) for element in struct]
    elif isinstance(struct, tuple):
        return tuple([convert_struct_to_ascii(element) for element in struct])
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
    idc.MakeComm(address, comment)
    # Always succeeds


def get_repeated_comment(address):
    if is_function_start(address):
        repeated_comment = idc.GetFunctionCmt(address, 1)
    else:
        repeated_comment = idc.RptCmt(address)

    if repeated_comment is None or len(repeated_comment) == 0:
        return None
    return repeated_comment


def set_repeated_comment(address, repeated_comment):
    if is_function_start(address):
        idc.SetFunctionCmt(address, repeated_comment, 1)
    else:
        idc.MakeRptCmt(address, repeated_comment)