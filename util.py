from pprint import pprint

DEBUG = True


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


def prin(s: str, color: bcolors = bcolors.NONE) -> None:
    if DEBUG:
        if color:
            print(color)
        pprint(s)
        if color:
            print(bcolors.ENDC)
