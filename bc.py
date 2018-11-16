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
#var = {}
dng_strcpy = []

# checking functions


def check_strcat(state):
    print("\nAnalyzing vulnerability due to strcat in", state)

    # source
    source_buf = state.get_reg_val('rsi')
    source = source_buf.get_val()
    src_len = variables[state.f_n][source].bytes_filled

    #destination
    destination_buf = state.get_reg_val('rdi')
    destination = destination_buf.get_val()
    dest_len = variables[state.f_n][destination].bytes
    dest_len_f = variables[state.f_n][destination].bytes_filled

    if src_len > (dest_len - dest_len_f):
        # now check what can be overflown
        print("Possible overflow by strcat: Buffer {} can be overflown by buffer {}".format(variables[state.f_n][destination].name, variables[state.f_n][source].name))

        total_length = dest_len_f + src_len
        check_rbp_overflow(state, total_length, variables[state.f_n][destination], 'strcat')
        check_var_overflow(state, total_length, variables[state.f_n][destination], 'strcat')
        check_ret_overflow(state, total_length, variables[state.f_n][destination], 'strcat')
        check_s_corruption(state, total_length, variables[state.f_n][destination], 'strcat')
        check_inavlidAcc_overflow(state, total_length, variables[state.f_n][destination], 'strcat')
    else:
        print("There is no strcat overflow possible here.")
        return

def check_strncat(state):

    print("\nAnalyzing vulnerability due to strncat in", state)

    # source
    source_buf = state.get_reg_val('rsi')
    source = source_buf.get_val()
    src_len = variables[state.f_n][source].bytes_filled

    input_len = state.get_reg_val('edx')
    input_len = input_len.get_val(True)
    #destination
    destination_buf = state.get_reg_val('rdi')
    destination = destination_buf.get_val()
    dest_len = variables[state.f_n][destination].bytes
    dest_len_f = variables[state.f_n][destination].bytes_filled

    if input_len > (dest_len - dest_len_f):

        if src_len > (dest_len - dest_len_f):
            # now check what can be overflown
            print("Possible overflow by strncat: Buffer {} can be overflown by buffer {}".format(variables[state.f_n][destination].name, variables[state.f_n][source].name))

            total_length = dest_len_f + src_len
            check_rbp_overflow(state, total_length, variables[state.f_n][destination], 'strncat')
            check_var_overflow(state, total_length, variables[state.f_n][destination], 'strncat')
            check_ret_overflow(state, total_length, variables[state.f_n][destination], 'strncat')
            check_s_corruption(state, total_length, variables[state.f_n][destination], 'strncat')
            check_inavlidAcc_overflow(state, total_length, variables[state.f_n][destination], 'strncat')
        else:
            print("There is no strncat overflow possible here.")
            return

    else:
        print("There is no strncat overflow possible here.")
        return

    return

def check_strncpy(state):
    print("\nAnalyzing vulnerability due to strncpy in", state)
    
    destination_buf = state.get_reg_val('rdi')
    destination = destination_buf.get_val()
    dest_len = variables[state.f_n][destination].bytes
    
    source_buf = state.get_reg_val('rsi')
    source = source_buf.get_val()
    src_len = variables[state.f_n][source].bytes_filled
    
    input_len = state.get_reg_val('edx')
    input_len = input_len.get_val(True)

    if src_len >input_len and input_len == dest_len:
        global dng_strcpy
        dng_strcpy.append(variables[state.f_n][destination].name)
        print(variables[state.f_n][destination].name)

    if input_len > dest_len:
        check_overflow_consequences(state, input_len, destination, "strcpy")
    else:
        return

def check_strcpy(state):

    print("\nAnalyzing vulnerability due to strcpy in", state)
    
    destination_buf = state.get_reg_val('rdi')
    destination = destination_buf.get_val()
    dest_len = variables[state.f_n][destination].bytes
    
    source_buf = state.get_reg_val('rsi')
    source = source_buf.get_val()
    src_len = variables[state.f_n][source].bytes_filled
    
    if src_len > dest_len:
        check_overflow_consequences(state, src_len, destination, "strcpy")
    elif variables[state.f_n][source].name in dng_strcpy:
        check_overflow_consequences(state, 9999, destination, "strcpy")
    else:
        return
    

def check_gets(state: State):
    print("\nAnalyzing vulnerability due to gets in", state)

    buf_address = state.get_reg_val('rdi')
    print("buf_address:", buf_address)

    seg = state.get_seg(buf_address)
    print('seg:', seg)

    # no need to check, we know it's there
    # check_rbp_overflow(state, input_length, buf, dng_func)
    vuln = jsonio.create_vulnerability("RBPOVERFLOW", state.f_n, 'gets', seg.var.name,
                                       state.inst['address'])
    jsonio.add_vulnerability(vuln)

    # no need to check, we know it's there
    # check_ret_overflow(state, input_length, buf, dng_func)
    vuln = jsonio.create_vulnerability("RETOVERFLOW", state.f_n, 'gets', seg.var.name,
                                       state.inst['address'])
    jsonio.add_vulnerability(vuln)

    # no need to check, we know it's there
    # check_s_corruption(state, input_length, buf, dng_func)
    vuln = jsonio.create_vulnerability("SCORRUPTION", state.f_n, 'gets', seg.var.name,
                                       state.inst['address'], overflown_address='rbp+0x10')
    jsonio.add_vulnerability(vuln)
    
    #vuln = jsonio.create_vulnerability("VAROVERFLOW", state.f_n, 'gets', seg.var.name,
    #                                               state.inst['address'], state.inst['address'])
    #jsonio.add_vulnerability(vuln)
    
    vuln = jsonio.create_vulnerability("INVALIDACCS", state.f_n, 'gets', seg.var.name,
                                                        state.inst['address'], overflown_address="rbp-0x10")
    jsonio.add_vulnerability(vuln)

    check_var_overflow(state, sys.maxsize, seg.var, 'gets')


def check_fgets(state: State) -> None:
    """Assumes the buffer gets loaded from rax and the input from esi"""
    print("\nAnalyzing vulnerability due to fgets in")
    print(state)

    input_len = state.get_reg_val('esi')
    input_len = input_len.get_val(True)

    buf_address = state.get_reg_val('rdi')
    buf_address = buf_address.get_val()

    check_overflow_consequences(state, input_len, buf_address, "fgets")


# helper functions for the check_* functions

def check_overflow_consequences(state: State, input_length: int, buf_address: int, dng_func: str) -> None:
    """ Knowing the length of the input, and the address of the buf, what can happen?"""

    # find the buf variable among the local vars of f_n
    buf = variables[state.f_n][buf_address]

    if dng_func == "gets":
        pass
    elif buf:
        print(buf)
        buf.fill(input_length)
        # TODO: check if because of nullcharacter at end of string of input, this has to be input_length < buf['bytes']
        if input_length > buf.bytes:
            # now check what can be overflown
            print("VULNERABILITY: Buffer can be overflown by", input_length - buf.bytes)

            check_rbp_overflow(state, input_length, buf, dng_func)
            check_var_overflow(state, input_length, buf, dng_func)
            check_ret_overflow(state, input_length, buf, dng_func)
            check_s_corruption(state, input_length, buf, dng_func)
            check_inavlidAcc_overflow(state, input_length, buf, dng_func)
        else:
            print("There is no buffer overflow possible here.")


def check_rbp_overflow(state: State, input_length: int, buf, instruction_name: str) -> None:
    """check for RBPOVERFLOW"""
    print("Offset of the buf_address heh", buf.rbp_distance)

    if abs(buf.rbp_distance) < input_length:
        # bufferoverflow can reach rbp
        vuln = jsonio.create_vulnerability("RBPOVERFLOW", state.f_n, instruction_name, buf.name,
                                           state.inst['address'])
        jsonio.add_vulnerability(vuln)


def check_ret_overflow(state: State, input_length: int, buf, instruction_name: str) -> None:
    """check for RETOVERFLOW"""
    print("Offset of the buf_address ",  buf.rbp_distance)

    # Assuming the rbp is 8 bytes long
    if abs(buf.rbp_distance) + 8 < input_length:
        # bufferoverflow can reach returnaddress
        vuln = jsonio.create_vulnerability("RETOVERFLOW", state.f_n, instruction_name, buf.name,
                                           state.inst['address'])
        jsonio.add_vulnerability(vuln)

def check_inavlidAcc_overflow(state: State, input_length: int, buf, instruction_name: str) -> None:
    """check for inavlidAcc"""
    print("Offset of the buf_address ",  buf.rbp_distance)
    
    #sort keys of vars in function f_n    
    keys = list(variables[state.f_n].keys())
    keys.sort(reverse=True)

    sum = 0
    for i in keys:
        sum -= variables[state.f_n][i].bytes
        if sum!= variables[state.f_n][i].rbp_distance:
            #Padding found
            #Base adress of the padding
            address = abs(variables[state.f_n][i].rbp_distance) - variables[state.f_n][i].bytes

            #convert to hexa and proper format
            address = "rbp-"+hex(address)

            #add vuln            
            vuln = jsonio.create_vulnerability("INVALIDACCS", state.f_n, instruction_name, buf.name,
                                                        state.inst['address'], overflown_address=address)
            jsonio.add_vulnerability(vuln)
            
            #update sum value, to check if there is more padding
            sum = variables[state.f_n][i].rbp_distance


def check_var_overflow(state: State, input_length: int, buf: dict, instruction_name: str) -> None:
    """check for VARIABLEOVERFLOW"""

    # loop through all variables in the function
    for v_address in variables[state.f_n]:
        v = variables[state.f_n][v_address]
        if (v.name != buf.name) and (buf.rbp_distance < v.rbp_distance):

            # check for each of these variables if they can be overflown
            print('Checking variable for overflow:', v.name)

            if abs(buf.rbp_distance) - abs(v.rbp_distance) < input_length:
                vuln = jsonio.create_vulnerability("VAROVERFLOW", state.f_n, instruction_name, buf.name,
                                                   state.inst['address'], v.name)
                jsonio.add_vulnerability(vuln)


def check_s_corruption(state: State, input_length: int, buf: dict, dng_func: str) -> None:
    """Check for SCORRUPTION in main"""
    if state.f_n == 'main':
        if input_length > abs(buf.rbp_distance) + 16:
            vuln = jsonio.create_vulnerability("SCORRUPTION", state.f_n, dng_func, buf.name,
                                               state.inst['address'], overflown_address='rbp+0x10')
            jsonio.add_vulnerability(vuln)


dangerous_functions = {'<gets@plt>': check_gets, '<strcpy@plt>': check_strcpy, '<strcat@plt>': check_strcat,
                       '<fgets@plt>': check_fgets, '<strncpy@plt>': check_strncpy, '<strncat@plt>': check_strncat}


def main(name: str):

    

    json_data = jsonio.parser(name)

    process_json(json_data)

    for state in dangerous_functions_occurring:
        dangerous_functions[state.called_fn](state)

    jsonio.write_json()
    
    return

if __name__ == "__main__":
    import sys

    main(sys.argv[1])
