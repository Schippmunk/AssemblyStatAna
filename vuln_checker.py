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


# checking functions


def check_strcat(state):
    print("\nAnalyzing vulnerability due to strcat in", state)

    # source
    source_buf = state.get_reg_val('rsi')
    source = source_buf.get_val()
    src_len = variables[state.f_n][source].bytes_filled
    print("Src_len",src_len)

    #destination
    destination_buf = state.get_reg_val('rdi')
    destination = destination_buf.get_val()
    dest_len = variables[state.f_n][destination].bytes
    dest_len_f = variables[state.f_n][destination].bytes_filled
    print("Dest_len: ",dest_len)

    print(src_len)
    print(dest_len)
    print(dest_len_f)
    if src_len > (dest_len - dest_len_f):
        # now check what can be overflown
        print("STRCAT VULNERABILITY: Buffer {} can be overflown by buffer {}".format(variables[state.f_n][destination].name, variables[state.f_n][source].name))

        total_length = dest_len_f + src_len
        check_rbp_overflow(state, total_length, variables[state.f_n][destination], 'strcat')
        check_var_overflow(state, total_length, variables[state.f_n][destination], 'strcat')
        check_ret_overflow(state, total_length, variables[state.f_n][destination], 'strcat')
        check_s_corruption(state, total_length, variables[state.f_n][destination], 'strcat')
        check_canarie_overflow(state, total_length, variables[state.f_n][destination], 'strcat')
    else:
        print("There is no STRCAT overflow possible here.")


def check_strncat(state):

    print("\nAnalyzing vulnerability due to strncat in", state)

    # source
    source_buf = state.get_reg_val('rsi')
    source = source_buf.get_val()
    src_len = variables[state.f_n][source].bytes_filled
    print("Src_len",src_len)


    input_len = state.get_reg_val('edx')
    input_len = input_len.get_val(True)
    #destination
    destination_buf = state.get_reg_val('rdi')
    destination = destination_buf.get_val()
    dest_len = variables[state.f_n][destination].bytes
    dest_len_f = variables[state.f_n][destination].bytes_filled
    print("Dest_len: ",dest_len)

    print(src_len)
    print(dest_len)
    print(dest_len_f)
    if src_len > (dest_len - dest_len_f):

        if src_len > (dest_len - dest_len_f):
            # now check what can be overflown
            print("STRNCAT VULNERABILITY: Buffer {} can be overflown by buffer {}".format(variables[state.f_n][destination].name, variables[state.f_n][source].name))

            total_length = dest_len_f + src_len
            check_rbp_overflow(state, total_length, variables[state.f_n][destination], 'strncat')
            check_var_overflow(state, total_length, variables[state.f_n][destination], 'strncat')
            check_ret_overflow(state, total_length, variables[state.f_n][destination], 'strncat')
            check_s_corruption(state, total_length, variables[state.f_n][destination], 'strncat')
            check_canarie_overflow(state, total_length, variables[state.f_n][destination], 'strncat')
        else:
            print("There is no STRNCAT overflow possible here.")

    else:
        print("There is no STRNCAT overflow possible here.")

    return

def check_strncpy(state):
    destination_buf = state.get_reg_val('rdi')
    destination = destination_buf.get_val()
    dest_len = variables[state.f_n][destination].bytes
    print("Dest_len: ",dest_len)
    
    input_len = state.get_reg_val('edx')
    input_len = input_len.get_val(True)
    print("input_len:", input_len)

    if input_len > dest_len:
        check_overflow_consequences(state, input_len, destination, "strcpy")
    else:
        print("Strncpy: Source buffer has a smaller size than destination buffer: No vulnerability :-)")

def check_strcpy(state):

    print("\nAnalyzing vulnerability due to strcpy in", state)
    
    destination_buf = state.get_reg_val('rdi')
    destination = destination_buf.get_val()
    dest_len = variables[state.f_n][destination].bytes
    print("Dest_len: ",dest_len)
    
    source_buf = state.get_reg_val('rsi')
    source = source_buf.get_val()
    src_len = variables[state.f_n][source].bytes_filled
    print("Src_len",src_len)
    
    if src_len > dest_len:
        check_overflow_consequences(state, src_len, destination, "strcpy")
    else:
        print("Strcpy: Source buffer has a smaller size than destination buffer: No vulnerability :-)")
    

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
                                                        state.inst['address'], overflown_address=state.inst['address'])
    jsonio.add_vulnerability(vuln)

    check_var_overflow(state, sys.maxsize, seg.var, 'gets')


def check_fgets(state: State) -> None:
    """Assumes the buffer gets loaded from rax and the input from esi"""
    print("\nAnalyzing vulnerability due to fgets in")
    print(state)

    input_len = state.get_reg_val('esi')
    input_len = input_len.get_val(True)
    print("input_len:", input_len)

    buf_address = state.get_reg_val('rdi')
    buf_address = buf_address.get_val()
    print("buf_address:", buf_address)

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
            check_canarie_overflow(state, input_length, buf, dng_func)
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

def check_canarie_overflow(state: State, input_length: int, buf, instruction_name: str) -> None:
    """check for CanarieOVERFLOW"""
    print("Offset of the buf_address ",  buf.rbp_distance)

    # Assuming the rbp is 8 bytes long
    if abs(buf.rbp_distance) - 8 < input_length:
        #TODO CHANGE OVERFLOWN_ADDRESS TO ACTUAL CANARIE ADRESS (maybe?)
        vuln = jsonio.create_vulnerability("INVALIDACCS", state.f_n, instruction_name, buf.name,
                                                        state.inst['address'], overflown_address=state.inst['address'])
        jsonio.add_vulnerability(vuln)


def check_var_overflow(state: State, input_length: int, buf: dict, instruction_name: str) -> None:
    """check for VARIABLEOVERFLOW"""

    # loop through all variables in the function
    for v_address in variables[state.f_n]:
        v = variables[state.f_n][v_address]
        print("YEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
        print(v.name)
        if (v.name != buf.name) and (buf.rbp_distance < v.rbp_distance):

            # check for each of these variables if they can be overflown
            print('Checking variable for overflow:', v.name)

            if abs(buf.rbp_distance) - abs(v.rbp_distance) < input_length:
                print("TYPEERU:",v.type)
                #if v['type'] == 'padding':
                    # a padding variable was overflown
                #    vuln = jsonio.create_vulnerability("INVALIDACCS", state.f_n, instruction_name, buf['name'],
                                            #            state.inst['address'], overflown_address=v['address'])
                #    jsonio.add_vulnerability(vuln)

                # an actual variable was overflown
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
    # checking this if state.f_n is not main requires a lot more work, because we don't know how far the rbp of
    # state.f_n is a way from the rbp of main
    

# utility functions


dangerous_functions = {'<gets@plt>': check_gets, '<strcpy@plt>': check_strcpy, '<strcat@plt>': check_strcat,
                       '<fgets@plt>': check_fgets, '<strncpy@plt>': check_strncpy, '<strncat@plt>': check_strncat}


def main(name: str):

    

    json_data = jsonio.parser(name)

    process_json(json_data)


    # print statements
    #print_list()
    #pprint(variables)
    # pprint(dangerous_functions_occurring)

    # analyze each dangerous function call
    for state in dangerous_functions_occurring:
        dangerous_functions[state.called_fn](state)

    jsonio.write_json()
    
    return

if __name__ == "__main__":
    import sys

    main(sys.argv[1])
