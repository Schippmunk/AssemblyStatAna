from pprint import pprint

# debug mode?
DEBUG = False


class bcolors:
    """ ASCII Colors for printing"""

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


def prin(s: str, param='', color: bcolors = bcolors.NONE) -> None:
    """Only prints if debug is enabled, takes color parameters"""
    if DEBUG:
        if color:
            print(color)
        if param:
            pprint(s, param)
        else:
            pprint(s)
        if color:
            print(bcolors.ENDC)
