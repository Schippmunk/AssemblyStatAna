# allows annotating states from program.py even though State is declared afterwards
from __future__ import annotations
# regular expressions used to match addresses
import re

# our other modules
import jsonio
from program import *
from util import *

# pprint used for debugging
from pprint import pprint

# holds all information about the program
data = {}
p = {}
var = {}

reg_matcher = {'relative_rbp_trimmed': {'matcher': re.compile('rbp-0x\d+'),
                                        'converter': lambda x: int(x[4:], 16)},
               'relative_rbp': {'matcher': re.compile('\[rbp-0x\d+\]'),
                                'converter': lambda x: int(x[5:len(x) - 1], 16)},
               'hex_num': {'matcher': re.compile('0x\d+'),
                           'converter': lambda x: int(x, 16)},
               'all': {'matcher': re.compile('rbp-0x\d+|\[rbp-0x\d+\]|0x\d+')}}


# checking functions


def check_gets(state):
    print("\nAnalyzing vulnerability due to gets in", state)


def check_strncpy(state):
    print("\nAnalyzing vulnerability due to strncpy in", state)


def check_strcat(state):
    print("\nAnalyzing vulnerability due to strcat in", state)


def check_strncat(state):
    print("\nAnalyzing vulnerability due to strncat in", state)


def check_strcpy(state):
    print("\nAnalyzing vulnerability due to strcpy in", state)


def check_fgets(state: State) -> None:
    """Assumes the buffer gets loaded from rax and the input from esi"""
    print("\nAnalyzing vulnerability due to fgets in")
    print(state)

    input_len = find_reg_val(state, 'esi', 'hex_num', True)
    print("input_len:", input_len)

    buf_address = find_reg_val(state, 'rax', 'relative_rbp', False)
    buf_address = my_str_trim(buf_address)
    print("buf_address:", buf_address)

    check_overflow_consequences(state, input_len, buf_address)


# helper functions for the check_* functions

def check_overflow_consequences(state: State, input_length: int, buf_address: str) -> None:
    """ Knowing the length of the input, and the address of the buf, what can happen?"""

    # find the buf variable among the local vars of f_n
    buf = get_var(state.f_n, buf_address)
    if buf:
        print("Buffer is of size", buf['bytes'])
        # TODO: check if because of nullcharacter at end of string of input, this has to be input_length < buf['bytes']
        if input_length > buf['bytes']:
            # now check what can be overflown
            print("VULNERABILITY: Buffer can be overflown by", input_length - buf['bytes'])

            check_rbp_overflow(state, input_length, buf, 'fgets')
            check_var_overflow(state, input_length, buf, 'fgets')
            check_invalid_address()
        else:
            print("There is no buffer overflow possible here.")


def check_rbp_overflow(state, input_length: int, buf, instruction_name: str) -> None:
    """check for RBPOVERFLOW"""
    print("Offset of the buf_address", buf['rbp_distance'])

    if buf['rbp_distance'] < input_length:
        # bufferoverflow can reach rbp
        vuln = jsonio.create_vulnerability("RBPOVERFLOW", state.f_n, instruction_name, buf['name'],
                                           state.inst['address'])
        jsonio.add_vulnerability(vuln)


def check_var_overflow(state, input_length: int, buf, instruction_name: str) -> None:
    """check for VARIABLEOVERFLOW"""

    # loop through all variables in the function
    for v in var[state.f_n]:
        if not v['name'] == buf['name']:

            # check for each of these variables if they can be overflown
            print('Checking variable for overflow:', v['name'])

            # buffer_rbp_distance - variable_rbp_distance describes the distance between
            # buffer_address and input_address
            if buf['rbp_distance'] - v['rbp_distance'] < input_length:
                vuln = jsonio.create_vulnerability("VAROVERFLOW", state.f_n, instruction_name, buf['name'],
                                                   state.inst['address'], v['name'])
                jsonio.add_vulnerability(vuln)


def check_invalid_address():
    pass


# utility functions

def get_var(f_n: str, address: str) -> dict:
    """Returns the whole variable dictionary of function f_n, if address matches the variable's address"""
    for v in var[f_n]:
        if v['address'] == address:
            return v
    print("get_var ERROR: No such address {} in function {}".format(address, f_n))


def find_reg_val(state: State, reg: str, matcher: str, apply_converter: bool):
    """ This very useful method uses reg_val to find the value of a register reg, given a function and position"""

    reg_val = state.reg_vals[reg]
    if reg_matcher[matcher]['matcher'].match(reg_val):
        if apply_converter:
            reg_val = reg_matcher[matcher]['converter'](reg_val)
        return reg_val
    else:
        # TODO: find it in the parent of the state
        print("ERRROR: unknown register, or does not match", reg_val)


# initialization functions


def add_variable_positions() -> None:
    """Goes through all variables of all functions.

    Adds attribute rbpdistance to it, that is the decimal integer distance of it to rbp"""

    global var

    for f_n in var.keys():
        for v in var[f_n]:
            var_address = v['address']
            if reg_matcher['relative_rbp_trimmed']['matcher'].match(var_address):
                var_rbp_distance = reg_matcher['relative_rbp_trimmed']['converter'](var_address)
                v['rbp_distance'] = var_rbp_distance
            else:
                print('ERROR in add_variable_positions: value of variable_address does not match re, is', var_address)


dangerous_functions = {'<gets@plt>': check_gets, '<strcpy@plt>': check_strcpy, '<strcat@plt>': check_strcat,
                       '<fgets@plt>': check_fgets, '<strncpy@plt>': check_strncpy, '<strncat@plt>': check_strncat}


def main(name: str):
    global data, var, p, dangerous_functions

    json_data = jsonio.parser(name)

    # not sure if data will be needed after this, or if p is good enough
    data = json_data['data']
    var = json_data['vars']

    pr = process_json(data)
    p = pr[0]
    dan_fun_occ = pr[1]

    add_variable_positions()

    print_list()
    pprint(var)
    pprint(dangerous_functions_occurring)

    for state in dan_fun_occ:
        dangerous_functions[state.called_fn](state)


if __name__ == "__main__":
    import sys

    main(sys.argv[1])
