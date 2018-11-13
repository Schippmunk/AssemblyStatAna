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


# checking functions

def change_var_written(v, new_bytes):
    v['bytes_filled'] = v['bytes_filled'] + new_bytes


def check_strcat(state):
    print("\nAnalyzing vulnerability due to strcat in", state)

    # source
    src_address = my_str_trim(find_reg_val(state, 'rsi', 'relative_rbp'))
    print("src_address:", src_address)

    # dest
    dest_address = my_str_trim(find_reg_val(state, 'rdi', 'relative_rbp'))
    print("dest_dress:", dest_address)

    src = get_var(state.f_n, src_address)
    dest = get_var(state.f_n, dest_address)

    print("Source has {} bytes filled".format(src['bytes_filled']))
    print("Destination has {} out of {} bytes filled".format(dest['bytes_filled'], dest['bytes']))

    # TODO: check if because of nullcharacter at end of string of input, this has to be input_length < buf['bytes']
    if src['bytes_filled'] > (dest['bytes'] - dest['bytes_filled']):
        # now check what can be overflown
        print("STRCAT VULNERABILITY: Buffer {} can be overflown by buffer {}".format(dest['name'], src['name']))

        total_length = dest['bytes_filled'] + src['bytes_filled']
        check_rbp_overflow(state, total_length, dest, 'strcat')
        check_var_overflow(state, total_length, dest, 'strcat')
        check_ret_overflow(state, total_length, dest, 'strcat')
        check_s_corruption(state, total_length, dest, 'strcat')
    else:
        print("There is no STRCAT overflow possible here.")


def check_strncat(state):
    print("\nAnalyzing vulnerability due to strncat in", state)


def check_gets(state: State):
    print("\nAnalyzing vulnerability due to gets in", state)

    buf_address = find_reg_val(state, 'rdi', 'relative_rbp')
    print("buf_address:", buf_address)
    buf_address = my_str_trim(buf_address)

    check_overflow_consequences(state, sys.maxsize, buf_address, "gets")


def check_strncpy(state):
    print("\nAnalyzing vulnerability due to strncpy in", state)

    destination = find_reg_val(state, 'rdi', 'relative_rbp')
    print("destination:", destination)

    source = find_reg_val(state, 'rsi', 'relative_rbp')
    print("source:", source)
    
    cpy_len = find_reg_val(state, 'esi', 'hex_num')
    cpy_len = reg_matcher['hex_num']['converter'](cpy_len)
    
    print("cpy_len:", cpy_len)
    
    len_dest = get_var(state.f_n,destination)['bytes']

    if cpy_len > len_dest:
        check_overflow_consequences(state, cpy_len, destination, "strncpy")
    else:
        print("Strncpy: Destination buffer has a bigger size than the amount to be copied from source: No vulnerability :-)")

    # now see if the minimum of the limit and the length of the buf at buf_address exceed buf2


def check_strcpy(state):
    print("\nAnalyzing vulnerability due to strcpy in", state)

    destination = find_reg_val(state, 'rdi', 'relative_rbp')
    print("destination:", destination)

    source = find_reg_val(state, 'rsi', 'relative_rbp')
    print("source:", source)

    # compute input_length to be length of buffer at buf_address
    # then call
    source = my_str_trim(source)
    destination = my_str_trim(destination)

    len_source = get_var(state.f_n, source)['bytes_filled']
    len_dest = get_var(state.f_n, destination)['bytes']
    print("Source:",len_source)
    print("Dest:",len_dest)

    if len_source>=0 and len_dest>=0 and len_source > len_dest:
        check_overflow_consequences(state, len_source, destination, "strcpy")
    else:
        print("Strcpy: Source buffer has a smaller size than destination buffer: No vulnerability :-)")


def check_fgets(state: State) -> None:
    """Assumes the buffer gets loaded from rax and the input from esi"""
    print("\nAnalyzing vulnerability due to fgets in")
    print(state)

    input_len = find_reg_val(state, 'rsi', 'hex_num')
    #input_len = reg_matcher['hex_num']['converter'](input_len)
    print("input_len:", input_len)

    buf_address = find_reg_val(state, 'rdi', 'relative_rbp')
    #buf_address = my_str_trim(buf_address)
    print("buf_address:", buf_address)

    check_overflow_consequences(state, input_len, buf_address, "fgets")


# helper functions for the check_* functions

def check_overflow_consequences(state: State, input_length: int, buf_address: str, dng_func: str) -> None:
    """ Knowing the length of the input, and the address of the buf, what can happen?"""

    # find the buf variable among the local vars of f_n
    buf = get_var(state.f_n, buf_address)

    if dng_func == "gets":
        # no need to check, we know it's there
        # check_rbp_overflow(state, input_length, buf, dng_func)
        vuln = jsonio.create_vulnerability("RBPOVERFLOW", state.f_n, dng_func, buf['name'],
                                           state.inst['address'])
        jsonio.add_vulnerability(vuln)

        check_var_overflow(state, input_length, buf, dng_func)

        # no need to check, we know it's there
        # check_ret_overflow(state, input_length, buf, dng_func)
        vuln = jsonio.create_vulnerability("RETOVERFLOW", state.f_n, dng_func, buf['name'],
                                           state.inst['address'])
        jsonio.add_vulnerability(vuln)

        # no need to check, we know it's there
        # check_s_corruption(state, input_length, buf, dng_func)
        vuln = jsonio.create_vulnerability("SCORRUPTION", state.f_n, dng_func, buf['name'],
                                           state.inst['address'], overflown_address='rbp+0x10')
        jsonio.add_vulnerability(vuln)
    elif buf:
        change_var_written(buf, input_length)

        print("Buffer is of size", buf['bytes'])
        # TODO: check if because of nullcharacter at end of string of input, this has to be input_length < buf['bytes']
        if input_length > buf['bytes']:
            # now check what can be overflown
            print("VULNERABILITY: Buffer can be overflown by", input_length - buf['bytes'])

            check_rbp_overflow(state, input_length, buf, dng_func)
            check_var_overflow(state, input_length, buf, dng_func)
            check_ret_overflow(state, input_length, buf, dng_func)
            check_s_corruption(state, input_length, buf, dng_func)
        else:
            print("There is no buffer overflow possible here.")


def check_rbp_overflow(state: State, input_length: int, buf, instruction_name: str) -> None:
    """check for RBPOVERFLOW"""
    print("Offset of the buf_address", buf['rbp_distance'])

    if buf['rbp_distance'] < input_length:
        # bufferoverflow can reach rbp
        vuln = jsonio.create_vulnerability("RBPOVERFLOW", state.f_n, instruction_name, buf['name'],
                                           state.inst['address'])
        jsonio.add_vulnerability(vuln)


def check_ret_overflow(state: State, input_length: int, buf, instruction_name: str) -> None:
    """check for RETOVERFLOW"""
    print("Offset of the buf_address", buf['rbp_distance'])

    # Assuming the rbp is 8 bytes long
    if buf['rbp_distance'] + 8 < input_length:
        # bufferoverflow can reach returnaddress
        vuln = jsonio.create_vulnerability("RETOVERFLOW", state.f_n, instruction_name, buf['name'],
                                           state.inst['address'])
        jsonio.add_vulnerability(vuln)


def check_var_overflow(state: State, input_length: int, buf, instruction_name: str) -> None:
    """check for VARIABLEOVERFLOW"""

    # loop through all variables in the function
    for v in var[state.f_n]:
        if (v['name'] != buf['name']) and (buf['rbp_distance'] > v['rbp_distance']):

            # check for each of these variables if they can be overflown
            print('Checking variable for overflow:', v['name'])

            # buffer_rbp_distance - variable_rbp_distance describes the distance between
            # buffer_address and input_address
            if buf['rbp_distance'] - v['rbp_distance'] < input_length:
                if v['type'] == 'padding':
                    # a padding variable was overflown
                    vuln = jsonio.create_vulnerability("INVALIDACCS", state.f_n, instruction_name, buf['name'],
                                                       state.inst['address'], overflown_address=v['address'])
                    jsonio.add_vulnerability(vuln)
                else:
                    # an actual variable was overflown
                    vuln = jsonio.create_vulnerability("VAROVERFLOW", state.f_n, instruction_name, buf['name'],
                                                       state.inst['address'], v['name'])
                    jsonio.add_vulnerability(vuln)


def check_s_corruption(state: State, input_length: int, buf: dict, dng_func: str) -> None:
    """Check for SCORRUPTION in main"""
    if state.f_n == 'main':
        if input_length > buf['rbp_distance'] + 16:
            vuln = jsonio.create_vulnerability("SCORRUPTION", state.f_n, dng_func, buf['name'],
                                               state.inst['address'], overflown_address='rbp+0x10')
            jsonio.add_vulnerability(vuln)
    # checking this if state.f_n is not main requires a lot more work, because we don't know how far the rbp of
    # state.f_n is a way from the rbp of main
    

# utility functions

def get_var(f_n: str, address: str) -> dict:
    """Returns the whole variable dictionary of function f_n, if address matches the variable's address"""
    for v in var[f_n]:
        if v['address'] == address:
            return v
    print("get_var ERROR: No such address {} in function {}".format(address, f_n))


def find_reg_val(state: State, reg: str, matcher: str):
    """ This very useful method uses reg_val to find the value of a register reg, given a function and position"""

    if reg in state.reg_vals.keys():
        reg_val = state.reg_vals[reg]
        return reg_val
    else:
        print("ERROR: unkown register value of ", reg)


dangerous_functions = {'<gets@plt>': check_gets, '<strcpy@plt>': check_strcpy, '<strcat@plt>': check_strcat,
                       '<fgets@plt>': check_fgets, '<strncpy@plt>': check_strncpy, '<strncat@plt>': check_strncat}


def main(name: str):
    global data, var, p, dangerous_functions

    json_data = jsonio.parser(name)

    pr = process_json(json_data)
    p = pr[0]
    var = pr[1]
    dan_fun_occ = pr[2]

    # print statements
    # print_list()
    # pprint(var)
    # pprint(dangerous_functions_occurring)
    return
    # analyze each dangerous function call
    for state in dan_fun_occ:
        dangerous_functions[state.called_fn](state)
    return
    jsonio.write_json()


if __name__ == "__main__":
    import sys

    main(sys.argv[1])
