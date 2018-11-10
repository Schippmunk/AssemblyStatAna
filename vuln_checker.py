import jsonio

# pprint used for debugging
from pprint import pprint

# regular expressions used to match adresses in fgets
import re

# holds all information about the program
p_data = {}


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


def check_fgets(f_n, instruction):
    print("\nAnalyzing vulnerability due to fgets in", f_n)

    #pprint(p_data)

    # find the second parameter, the length that is read by fgets. It gets moved two positions before the gets call
    # this call assumes that the parameter is a hardcoded number, not a variable
    # TODO: write a general method for this, that maybe even treats the case where the parameter is not hardcoded
    input_length = get_instruction(f_n, instruction['pos'] - 2)['args']['value']
    regular_expression = re.compile('0x\d+')
    if regular_expression.match(input_length):
        input_length = int(input_length, 0)
        print("Maximum input length is", input_length)
    else:
        print("ERROR: inputlenght is not a hexadecimal number, but", input_length)

    # find the buffer to copy into
    # load the instruction
    buf_inst = get_instruction(f_n, instruction['pos'] - 3)
    # in the the first 5 tests at least, the buffer is only loaded using lea, and the address depends directly on rbp
    if buf_inst['op'] == 'lea':
        buf_address = buf_inst['args']['value']
        # clip off [, ]
        buf_address = buf_address[1:len(buf_address) - 1]

        check_overflow_consequences(f_n, instruction, input_length, buf_address)
    else:
        print('ERROR: Buffer not loaded using lea')





# the basic dangerous functions we are considering
dangerous_functions = {'<gets@plt>': check_gets, '<strcpy@plt>': check_strcpy, '<strcat@plt>': check_strcat,
                       '<fgets@plt>': check_fgets, '<strncpy@plt>': check_strncpy, '<strncat@plt>': check_strncat}





# helper functions for the check_* functions




def check_overflow_consequences(f_n, instruction, input_length, buf_address):
    """ Knowing the length of the input, and the address of the buf, what can happen?"""

    # find the buf variable among the local vars of f_n
    buf = get_var(f_n, buf_address)
    if buf:
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




def get_instruction(f_n, number):
    """Returns the dictionray of the nunmber-th instruction of function f_n"""

    return p_data[f_n]['instructions'][number - 3]


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


def check_buffer_vuln():
    """Goes through the instructions, and delegates analysis of detected dangerous functions"""

    for f_n in p_data.keys():
        for instr in p_data[f_n]['instructions']:
            if instr['op'] == 'call':
                if instr['args']['fnname'] in dangerous_functions:
                    dangerous_functions[instr['args']['fnname']](f_n, instr)

def main(name):
    global p_data
    p_data = jsonio.parser(name)

    if(p_data):
        add_variable_positions()
        check_buffer_vuln()


if __name__ == "__main__":
    import sys

    main(sys.argv[1])
