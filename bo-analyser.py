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
dng_strcpy = []


# checking functions


def check_strcat(state):
    # source
    source_buf = state.get_reg_val('rsi')
    source = source_buf.get_val()
    src_len = variables[state.f_n][source].bytes_filled

    # destination
    destination_buf = state.get_reg_val('rdi')
    destination = destination_buf.get_val()
    dest_len = variables[state.f_n][destination].bytes
    dest_len_f = variables[state.f_n][destination].bytes_filled

    if src_len > (dest_len - dest_len_f):
        # now check what can be overflown

        total_length = dest_len_f + src_len
        check_rbp_overflow(state, total_length, variables[state.f_n][destination], 'strcat')
        check_var_overflow(state, total_length, variables[state.f_n][destination], 'strcat')
        check_ret_overflow(state, total_length, variables[state.f_n][destination], 'strcat')
        check_s_corruption(state, total_length, variables[state.f_n][destination], 'strcat')
        check_inavlidAcc_overflow(state, total_length, variables[state.f_n][destination], 'strcat')
    else:
        return


def check_strncat(state):
    # source
    source_buf = state.get_reg_val('rsi')
    source = source_buf.get_val()
    # check how many bytes are actually filled in source buffer
    src_len = variables[state.f_n][source].bytes_filled

    input_len = state.get_reg_val('edx')
    input_len = input_len.get_val(True)

    destination_buf = state.get_reg_val('rdi')
    destination = destination_buf.get_val()
    # check size of destination buffer
    dest_len = variables[state.f_n][destination].bytes
    # check how many bytes are actually filled in destination buffer
    dest_len_f = variables[state.f_n][destination].bytes_filled

    # first check if the number bytes to be appended is greater than the free space of destination
    if input_len > (dest_len - dest_len_f):
        # now check if the number bytes in the source that are filled is greater than the free space of destination
        if src_len > (dest_len - dest_len_f):
            # at this point, buffer overflow is possible, check what are the consequences

            if src_len > input_len:
                total_length = dest_len_f + input_len

            else:
                total_length = dest_len_f + src_len

            check_rbp_overflow(state, total_length, variables[state.f_n][destination], 'strncat')
            check_var_overflow(state, total_length, variables[state.f_n][destination], 'strncat')
            check_ret_overflow(state, total_length, variables[state.f_n][destination], 'strncat')
            check_s_corruption(state, total_length, variables[state.f_n][destination], 'strncat')
            check_inavlidAcc_overflow(state, total_length, variables[state.f_n][destination], 'strncat')
        else:
            return

    else:
        return

    return


def check_strncpy(state):
    destination_buf = state.get_reg_val('rdi')
    destination = destination_buf.get_val()
    dest_len = variables[state.f_n][destination].bytes

    source_buf = state.get_reg_val('rsi')
    source = source_buf.get_val()
    src_len = variables[state.f_n][source].bytes_filled

    input_len = state.get_reg_val('edx')
    input_len = input_len.get_val(True)

    if src_len > input_len and input_len == dest_len:
        global dng_strcpy
        dng_strcpy.append(variables[state.f_n][destination].name)

    if input_len > dest_len:
        check_overflow_consequences(state, input_len, destination, "strncpy")
    else:
        return


def check_strcpy(state):
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
    buf_address = state.get_reg_val('rdi')
    seg = state.get_seg(buf_address)

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

    # vuln = jsonio.create_vulnerability("VAROVERFLOW", state.f_n, 'gets', seg.var.name,
    #                                               state.inst['address'], state.inst['address'])
    # jsonio.add_vulnerability(vuln)

    vuln = jsonio.create_vulnerability("INVALIDACCS", state.f_n, 'gets', seg.var.name,
                                       state.inst['address'], overflown_address='rbp-0x10')
    jsonio.add_vulnerability(vuln)

    check_var_overflow(state, sys.maxsize, seg.var, 'gets')


def check_fgets(state: State) -> None:
    """Assumes the buffer gets loaded from rax and the input from esi"""

    input_len = state.get_reg_val('esi')
    input_len = input_len.get_val(True)

    buf_address = state.get_reg_val('rdi')
    buf_address = buf_address.get_val()

    check_overflow_consequences(state, input_len, buf_address, "fgets")


def check_overflow_consequences(state: State, input_length: int, buf_address: int, dng_func: str) -> None:
    """ Knowing the length of the input, and the address of the buf, what can happen?"""

    # find the buf variable among the local vars of f_n
    buf = variables[state.f_n][buf_address]

    if dng_func == "gets":
        pass
    elif buf:
        buf.fill(input_length)
        # TODO: check if because of nullcharacter at end of string of input, this has to be input_length < buf['bytes']
        if input_length > buf.bytes:
            # now check what can be overflown
            check_rbp_overflow(state, input_length, buf, dng_func)
            check_var_overflow(state, input_length, buf, dng_func)
            check_ret_overflow(state, input_length, buf, dng_func)
            check_s_corruption(state, input_length, buf, dng_func)
            check_inavlidAcc_overflow(state, input_length, buf, dng_func)
        else:
            return


def check_rbp_overflow(state: State, input_length: int, buf, instruction_name: str) -> None:
    """check for RBPOVERFLOW"""

    if abs(buf.rbp_distance) < input_length:
        # bufferoverflow can reach rbp
        vuln = jsonio.create_vulnerability("RBPOVERFLOW", state.f_n, instruction_name, buf.name,
                                           state.inst['address'])
        jsonio.add_vulnerability(vuln)


def check_ret_overflow(state: State, input_length: int, buf, instruction_name: str) -> None:
    """check for RETOVERFLOW"""

    # Assuming the rbp is 8 bytes long
    if abs(buf.rbp_distance) + 8 < input_length:
        # bufferoverflow can reach returnaddress
        vuln = jsonio.create_vulnerability("RETOVERFLOW", state.f_n, instruction_name, buf.name,
                                           state.inst['address'])
        jsonio.add_vulnerability(vuln)


def check_inavlidAcc_overflow(state: State, input_length: int, buf, instruction_name: str) -> None:
    """check for inavlidAcc"""

    # sort keys of vars in function f_n
    keys = list(variables[state.f_n].keys())
    keys.sort(reverse=True)

    sum = 0
    for i in keys:
        sum -= variables[state.f_n][i].bytes
        if sum != variables[state.f_n][i].rbp_distance:
            # Padding found
            # Base adress of the padding
            address = abs(variables[state.f_n][i].rbp_distance) - variables[state.f_n][i].bytes

            # convert to hexa and proper format
            address = "rbp-" + hex(address)

            # add vuln
            vuln = jsonio.create_vulnerability("INVALIDACCS", state.f_n, instruction_name, buf.name,
                                               state.inst['address'], overflown_address=address)
            jsonio.add_vulnerability(vuln)

            # update sum value, to check if there is more padding
            sum = variables[state.f_n][i].rbp_distance


def check_var_overflow(state: State, input_length: int, buf: dict, instruction_name: str) -> None:
    """check for VARIABLEOVERFLOW"""

    # loop through all variables in the function
    for v_address in variables[state.f_n]:
        v = variables[state.f_n][v_address]
        if (v.name != buf.name) and (buf.rbp_distance < v.rbp_distance):

            # check for each of these variables if they can be overflown

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
    # checking this if state.f_n is not main requires a lot more work, because we don't know how far the rbp of
    # state.f_n is a way from the rbp of main


dangerous_functions = {'<gets@plt>': check_gets, '<strcpy@plt>': check_strcpy, '<strcat@plt>': check_strcat,
                       '<fgets@plt>': check_fgets, '<strncpy@plt>': check_strncpy, '<strncat@plt>': check_strncat}


def main(name: str):
    """Delegates steps of the static analysis: reads file, processes it, saves output"""

    json_data = jsonio.parser(name)

    process_json(json_data)

    # analyze each dangerous function call
    for state in dangerous_functions_occurring:
        dangerous_functions[state.called_fn](state)

    jsonio.write_json()


if __name__ == "__main__":
    """Entry point of the program"""
    import sys

    main(sys.argv[1])
