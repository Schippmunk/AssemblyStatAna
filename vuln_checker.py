import jsonio

# pprint used for debugging
from pprint import pprint

# regular expressions used to match adresses in fgets
import re

p_data = {}
register_values = {}
ourfilename = '';


def check_gets(f_n, instruction):
    print(instruction)


def check_strcpy(f_n, instruction):
    print("\nAnalyzing vulnerability due to fgets in", f_n)


def check_strncpy(f_n, instruction):
    print(instruction)


def check_strcat(f_n, instruction):
    print(instruction)


def check_fgets(f_n, instruction):
    print("\nAnalyzing vulnerability due to fgets in", f_n)

    pprint(p_data)

    # find the second parameter, the length that is read by fgets. It gets moved two positions before the gets call
    # this call assumes that the parameter is a hardcoded number, not a variable
    inputlength = get_instruction(f_n, instruction['pos'] - 2)['args']['value']
    regular_expression = re.compile('0x\d+')
    if regular_expression.match(inputlength):
        inputlength = int(inputlength, 0)
        print("Maximum input length is", inputlength)
    else:
        print("ERROR: inputlenght is not a hexadecimal number, but", inputlength)
        return False

    # find the buffer to copy into
    # load the instruction
    bufferinst = get_instruction(f_n, instruction['pos'] - 3);
    # in the the first 5 tests at least, the buffer is only loaded using lea, and the address depends directly on rbp
    if bufferinst['op'] == 'lea':
        buffer_address = bufferinst['args']['value']
        # see if the address of the buffer saved in that operation is one we support
        regular_expression = re.compile('\[rbp-0x\d+\]')
        if regular_expression.match(buffer_address):
            # cool, buffer_address is of the form [rbp-0x50]

            # clip off [ and ]
            buffer_address = buffer_address[1:len(buffer_address)-1]

            # find the buffer variable among the local vars of f_n
            buffer = get_var(f_n, buffer_address)
            # get the amount of its bytes and convert base
            bufsize = int(buffer['bytes']);

            print("Size of the buffer is", bufsize)

            # TODO: check if because of nullcharacter at end of string of input, this has to be inputlength < bufsize
            if inputlength <= bufsize:
                print("Here is no bufferoverflow possible.")
                return True
            else:
                # now check what can be overflown
                print("VULNERABILITY: Buffer can be overflown by", inputlength - bufsize)

                ## check for INVALIDACCESS ##

                ## check vor VARIABLEOVERFLOW ##

                ## check for RBPOVERFLOW ##
                # parse distance between buffer_address and rbp
                buffer_rbp_distance = int(buffer_address[4:], 16)
                print("Offset of the buffer_address", buffer_rbp_distance)

                if buffer_rbp_distance < inputlength:
                    # bufferoverflow can reach rbp
                    vuln = jsonio.create_vulnerability("RBPOVERFLOW", f_n, 'fgets', buffer['name'], instruction['address'])
                    jsonio.add_vulnerability(vuln)

        else:
            print('ERROR: value of buffer_address is', buffer_address)
            return False
    else:
        print('ERROR: Buffer not loaded using lea')
        return False







def get_instruction(f_n, number):
    return p_data[f_n]['instructions'][number - 3]


def check_strncat(f_n, instruction):
    print(instruction)


def get_var(f_n, address):
    for var in p_data[f_n]['variables']:
        if var['address'] == address:
            return var
    print("get_var ERROR: No such address {} in function {}".format(address, f_n))


# basic, for now
dangerous_functions = {'<gets@plt>': check_gets, '<strcpy@plt>': check_strcpy, '<strcat@plt>': check_strcat,
                       '<fgets@plt>': check_fgets, '<strncpy@plt>': check_strncpy, '<strncat@plt>': check_strncat}


def check_buffer_vuln():
    for f_n in p_data.keys():
        for instr in p_data[f_n]['instructions']:
            if instr['op'] == 'call':
                if instr['args']['fnname'] in dangerous_functions:
                    dangerous_functions[instr['args']['fnname']](f_n, instr)


def check_vuln():
    check_buffer_vuln()

    # check_dangerous_func()


def main(name):
    global p_data
    p_data = jsonio.parser(name)

    check_vuln()
    '''if (not check_buffer_exists()):
        print("No buffers found in this file! :-)")
        return False'''


if __name__ == "__main__":
    import sys

    main(sys.argv[1])
