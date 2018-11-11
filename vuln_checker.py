# regular expressions used to match addresses
import re

# our other modules
import jsonio
import program

from util import *

# pprint used for debugging
from pprint import pprint


# holds all information about the program
data = {}
p = {}
var = {}
# the basic dangerous functions we are considering
dangerous_functions = {}

reg_matcher = {'relative_rbp_trimmed': {'matcher': re.compile('rbp-0x\d+'),
                                        'converter': lambda x: int(x[4:], 16)},
               'relative_rbp': {'matcher': re.compile('\[rbp-0x\d+\]'),
                                'converter': lambda x: int(x[5:len(x) - 1], 16)},
               'hex_num': {'matcher': re.compile('0x\d+'),
                           'converter': lambda x: int(x, 16)},
               'all': {'matcher': re.compile('rbp-0x\d+|\[rbp-0x\d+\]|0x\d+')}}





# checking functions


def check_gets(f_n, instruction):
    print("\nAnalyzing vulnerability due to gets in", f_n)
    print(instruction)


def check_strncpy(f_n, instruction):
    print("\nAnalyzing vulnerability due to strncpy in", f_n)
    print(instruction)

def check_strcat(f_n, instruction):
    print("\nAnalyzing vulnerability due to strcat in", f_n)
    print(instruction)

def check_strncat(f_n, instruction):
    print("\nAnalyzing vulnerability due to strncat in", f_n)
    print(instruction)

def check_strcpy(state):
    print("\nAnalyzing vulnerability due to strcpy in", state)


def check_fgets(state):
    """Assumes the buffer gets loaded from rax and the input from esi"""
    print("\nAnalyzing vulnerability due to fgets in", state)

    input_len = find_reg_val(state, 'esi', 'hex_num', True)
    print("input_len:", input_len)

    buf_address = find_reg_val(state, 'rax', 'relative_rbp', False)
    buf_address = my_str_trim(buf_address)
    print("buf_address:", buf_address)

    check_overflow_consequences(state, input_len, buf_address)


# helper functions for the check_* functions

def check_overflow_consequences(state, input_length, buf_address):
    """ Knowing the length of the input, and the address of the buf, what can happen?"""

    # find the buf variable among the local vars of f_n
    buf = get_var(state.f_n, buf_address)
    if buf:
        print("Buffer is of size", buf['bytes'])
        # TODO: check if because of nullcharacter at end of string of input, this has to be input_length < buf['bytes']
        if input_length > buf['bytes']:
            # now check what can be overflown
            print("VULNERABILITY: Buffer can be overflown by", input_length - buf['bytes'])

            check_rbp_overflow(state, input_length, buf)
            return
            check_var_overflow(state, input_length, buf)
            check_invalid_address()
        else:
            print("Here is no bufferoverflow possible.")



def check_rbp_overflow(f_n, instruction, input_length, buf):
    """check for RBPOVERFLOW"""

    print("Offset of the buf_address", buf['rbpdistance'])

    if buf['rbpdistance'] < input_length:
        # bufferoverflow can reach rbp
        vuln = jsonio.create_vulnerability("RBPOVERFLOW", f_n, 'fgets', buf['name'], instruction['address'])
        jsonio.add_vulnerability(vuln)


def check_var_overflow(f_n, instruction, input_length, buf):
    """check for VARIABLEOVERFLOW"""

    # loop through all variables in the function
    for var in p_data[f_n]['variables']:
        if not var['name'] == buf['name']:

            # check for each of these variables if they can be overflown
            print('Checking variable for overflow:', var['name'])

            # buffer_rbp_distance - variable_rbp_distance describes the distance between
            # buffer_address and input_address
            if buf['rbpdistance'] - var['rbpdistance'] < input_length:
                vuln = jsonio.create_vulnerability("VAROVERFLOW", f_n, 'fgets', buf['name'],
                                                   instruction['address'], var['name'])
                jsonio.add_vulnerability(vuln)

def check_invalid_address():
    pass



# utility functions

def find_last_existing_entry(dictionary, key):
    """ Goes downwards through the dictionary starting from key to find the first key that exists
    and returns the entry
    """
    while key >= 0:
        if key in dictionary.keys():
            return [key, dictionary[key]]
        else:
            key = key - 1
    print("ERROR: key" + str(key) + "not found in dictionary")
    pprint(dictionary)
    print("")


def get_instruction(f_n, number):
    """Returns the dictionray of the nunmber-th instruction of function f_n"""

    return p_data[f_n]['instructions'][number]


def get_var(f_n, address):
    """Returns the whole variable dictionary of function f_n, if address matches the variable's address"""
    for v in var[f_n]:
        if v['address'] == address:
            return v
    print("get_var ERROR: No such address {} in function {}".format(address, f_n))


def get_name_distance(var1, var2):
    """Given the name of two variable names, computes their distance in the stack"""

    for f_n in p_data.keys():
        for var in p_data[f_n]['variables']:
            if var['name'] == var1:
                var1 = var
            elif var['name'] == var2:
                var2 = var
    return get_var_distance(var1, var2)


def get_var_distance(var1, var2):
    """Given the name of two variables computes their distance in the stack"""

    return var1['rbpdistance'] - var2['rbpdistance']



def find_reg_val_old(f_n, pos, reg):
    """ This very useful method uses reg_val to find the value of a register reg, given a function and position"""
    entry = find_last_existing_entry(reg_val[reg][f_n]['none'], pos)

    if reg_matcher['all'].match(entry[1]):
        return entry[1]
    elif entry in reg_val.keys():
        return find_reg_val(f_n, entry[0], entry[1])
    else:
        # in this case the register has not been assigned to in the program
        # this is an error for now
        print("ERROR: cannot find value of register {} in function {} at position {}".format(reg, f_n, pos))
        return None

def find_reg_val(state, reg, matcher, apply_converter):
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


def add_variable_positions():
    """Goes through all variables of all functions.

    Adds attribute rbpdistance to it, that is the decimal integer distance of it to rbp"""

    global var

    for f_n in var.keys():
        for v in var[f_n]:
            var_address = v['address']
            if(reg_matcher['relative_rbp_trimmed']['matcher'].match(var_address)):
                var_rbp_distance = reg_matcher['relative_rbp_trimmed']['converter'](var_address)
                v['rbpdistance'] = var_rbp_distance
            else:
                print('ERROR in add_variable_positions: value of variable_address does not match re, is', var_address)


dangerous_functions = {'<gets@plt>': check_gets, '<strcpy@plt>': check_strcpy, '<strcat@plt>': check_strcat,
                           '<fgets@plt>': check_fgets, '<strncpy@plt>': check_strncpy, '<strncat@plt>': check_strncat}

def main(name):
    global data, var, p, dangerous_functions




    json_data = jsonio.parser(name)

    # not sure if data will be needed after this, or if p is good enough
    data = json_data['data']
    var = json_data['vars']

    pr = program.process_json(data)
    p = pr[0]
    dan_fun_occ = pr[1]

    add_variable_positions()

    #program.print_list()
    pprint(var)
    #pprint(dangerous_functions_occuring)



    for state in dan_fun_occ:
        dangerous_functions[state.called_fn](state)


if __name__ == "__main__":
    import sys
    main(sys.argv[1])
