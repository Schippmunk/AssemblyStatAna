from pprint import pprint
import re

DEBUG = True

reg_matcher = {'relative_rbp_trimmed': {'matcher': re.compile('rbp-0x\d+'),
                                        'converter': lambda x: int(x[4:], 16)},
               'relative_rbp': {'matcher': re.compile('\[rbp-0x\d+\]'),
                                'converter': lambda x: int(x[5:len(x) - 1], 16)},
               'hex_num': {'matcher': re.compile('0x\d+'),
                           'converter': lambda x: int(x, 16)},
               'all': {'matcher': re.compile('rbp-0x\d+|\[rbp-0x\d+\]|0x\d+')}}

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    NONE = ''


def my_str_trim(s: str) -> str:
    """returns the string with the first and last char removed"""
    return s[1:len(s) - 1]


def prin(s: str, param = '', color: bcolors = bcolors.NONE) -> None:
    if DEBUG:
        if color:
            print(color)
        if param:
            pprint(s, param)
        else:
            pprint(s)
        if color:
            print(bcolors.ENDC)
