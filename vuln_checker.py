# regular expressions used to match addresses
import re

import jsonio

# pprint used for debugging
from pprint import pprint


# holds all information about the program
p_data = {}
# dictionary with keys = registers and value = dictionary of value of register at each position in the program
reg_val = {}

reg_matcher = {'relative_rbp_trimmed': re.compile('rbp-0x\d+'),
               'relative_rbp': re.compile('\[rbp-0x\d+\]'),
               'hex_num': re.compile('0x\d+'),
               'all': re.compile('rbp-0x\d+|\[rbp-0x\d+\]|0x\d+')}





# checking functions


def check_gets(f_n, instruction):
    print("\nAnalyzing vulnerability due to gets in", f_n)
    print(instruction)


def check_strcpy(f_n, instruction):
    print("\nAnalyzing vulnerability due to strcpy in", f_n)
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


def check_fgets(f_n, inst):
    print("\nAnalyzing vulnerability due to fgets in", f_n)


    input_len = find_len_param(f_n, inst)
    print("New function input_len is", input_len)

    buf_address = find_buf_param(f_n, inst)
    check_overflow_consequences(f_n, inst, input_len, buf_address)

def find_len_param(f_n, instr):
    """ finds the the length parameter of fgets using reg_val"

    It assumes that it is always loaded from esi
    """

    #return reg_val['esi'][f_n][instr['pos']]
    #return find_last_existing_entry(reg_val['esi'][f_n], instr['pos'])
    rv = find_reg_val(f_n, instr['pos'], 'esi')
    if rv:
        if reg_matcher['hex_num'].match(rv):
            return int(rv, 16)
        else:
            print("ERROR: Value in rsi is not hex, but", rv)



def find_buf_param(f_n, instr):
    """ finds the buffer parameter in register rax in funciton main currently at instruction instr"""
    rv = find_reg_val(f_n, instr['pos'], 'rax')
    if rv:
        if reg_matcher['relative_rbp'].match(rv):
            return my_str_trim(rv)
        else:
            print("ERROR: Value in rax is not of type relative_rbp, but", rv)








# the basic dangerous functions we are considering
dangerous_functions = {'<gets@plt>': check_gets, '<strcpy@plt>': check_strcpy, '<strcat@plt>': check_strcat,
                       '<fgets@plt>': check_fgets, '<strncpy@plt>': check_strncpy, '<strncat@plt>': check_strncat}

# The dangerous functions that occur in the program get pushed to this list in analyze_reg_val_rec
dangerous_functions_occuring = []



# helper functions for the check_* functions




def check_overflow_consequences(f_n, instruction, input_length, buf_address):
    """ Knowing the length of the input, and the address of the buf, what can happen?"""

    # find the buf variable among the local vars of f_n
    buf = get_var(f_n, buf_address)
    if buf:
        print("Buffer is of size", buf['bytes'])
        # TODO: check if because of nullcharacter at end of string of input, this has to be input_length < buf['bytes']
        if input_length > buf['bytes']:
            # now check what can be overflown
            print("VULNERABILITY: Buffer can be overflown by", input_length - buf['bytes'])

            check_rbp_overflow(f_n, instruction, input_length, buf)
            check_var_overflow(f_n, instruction, input_length, buf)
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
    return False

def my_str_trim(str):
    """returns the string with the first and last char removed"""
    return str[1:len(str)-1]


def get_instruction(f_n, number):
    """Returns the dictionray of the nunmber-th instruction of function f_n"""

    return p_data[f_n]['instructions'][number]


def get_var(f_n, address):
    """Returns the whole variable dictionary of function f_n, if address matches the variable's address"""

    for var in p_data[f_n]['variables']:
        if var['address'] == address:
            return var
    print("get_var ERROR: No such address {} in function {}".format(address, f_n))
    return False


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



def find_reg_val(f_n, pos, reg):
    """ This very useful method uses reg_val to find the value of a register reg, given a function and position"""
    entry = find_last_existing_entry(reg_val[reg][f_n], pos)
    if reg_matcher['all'].match(entry[1]):
        return entry[1]
    elif entry in reg_val.keys():
        return find_reg_val(f_n, entry[0], entry[1])
    else:
        # in this case the register has not been assigned to in the program
        # this is an error for now
        print("ERROR: cannot find value of register {} in function {} at position {}".format(reg, f_n, pos))
        return None




# initialization functions




def add_variable_positions():
    """Goes through all variables of all functions.

    Adds attribute rbpdistance to it, that is the decimal integer distance of it to rbp"""

    global p_data

    for f_n in p_data.keys():
        for var in p_data[f_n]['variables']:
            var_address = var['address']
            re_relative_address = re.compile('rbp-0x\d+')
            if(re_relative_address.match(var_address)):
                var_rbp_distance = int(var_address[4:], 16)
                var['rbpdistance'] = var_rbp_distance
            else:
                print('ERROR in add_variable_positions: value of variable_address does not match re, is', var_address)

    print("The value of p_data is")
    pprint(p_data)



def check_buffer_vuln():
    """Goes through the instructions, and delegates analysis of detected dangerous functions"""

    #for f_n in p_data.keys():
    #    for instr in p_data[f_n]['instructions']:
    #        if instr['op'] == 'call':
    #            if instr['args']['fnname'] in dangerous_functions:
    #                dangerous_functions[instr['args']['fnname']](f_n, instr)
    for called_fn in dangerous_functions_occuring:
        dangerous_functions[called_fn['called_fn']](called_fn['f_n'],  called_fn['instr'])

def analyze_reg_val():
    """Calls analyze_reg_val with entry point main

    keys of reg_val: registers
    values: dictionary
        each dictionary has one key for each function that saves a value in the register
        the value is a dictionary
            each key is the position of the instruction in the function that saves the value
            the value is the value that is moved into the register

    TODO: Now it is easy to retrieve the value of a register if there are no generic functions.
    TODO: For the advanced case, it will be useful to add to the called function information on
    TODO: where they were called in the calling function
    """
    analyze_reg_val_rec('main')
    print("\nThe values of the registers during execution are")
    pprint(reg_val)

def analyze_reg_val_rec(f_n):
    """ sets up the global var reg_val starting at f_n

    Goes through the instructions and for each mov and lea, saves the new register value in the table reg_val
    Follows function calls
    """
    global reg_val
    for instruction in p_data[f_n]['instructions']:
        #print("Analyzing function {}. instruction {}".format(f_n, instruction['pos']))

        # Basically do the same for mov and lea operations
        if instruction['op'] == 'mov':
            reg = instruction['args']['dest']
            val = instruction['args']['value']
            pos = instruction['pos'];
            if not reg in reg_val:
                reg_val[reg] = {}
            if not f_n in reg_val[reg]:
                reg_val[reg][f_n] = {}
            reg_val[reg][f_n][pos] = val;
        elif instruction['op'] == 'lea':
            reg = instruction['args']['dest']
            val = instruction['args']['value']
            pos = instruction['pos'];
            if not reg in reg_val:
                reg_val[reg] = {}
            if not f_n in reg_val[reg]:
                reg_val[reg][f_n] = {}
            reg_val[reg][f_n][pos] = val;
        elif instruction['op'] == 'call':
            # follow function calls
            called_fn = instruction['args']['fnname']
            # remove <,>
            called_fn_trimmed = called_fn[1:len(called_fn)-1]
            if called_fn_trimmed in p_data.keys():
                # in this case we're calling a user defined generic function
                analyze_reg_val_rec(called_fn_trimmed)
            elif called_fn in dangerous_functions.keys():
                dangerous_call = {"called_fn": called_fn, "instr": instruction, "f_n": f_n}
                dangerous_functions_occuring.append(dangerous_call)

def main(name):
    global p_data
    p_data = jsonio.parser(name)

    if(p_data):
        add_variable_positions()
        analyze_reg_val()
        check_buffer_vuln()


if __name__ == "__main__":
    import sys

    main(sys.argv[1])
