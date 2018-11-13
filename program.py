from pprint import pprint
from pprint import pformat
from copy import copy, deepcopy
from util import *

# the raw imported json file
data = {}
# the processed list of states
p = []
# the states of p containing a call to a dangerous function
dangerous_functions_occurring = []

reg_match = {
    'dword_address': {'m': re.compile('DWORD PTR \[(rbp|rip)[+-]0x[0-9a-f]+\]'),
                      'c': lambda x: int(x[15:len(x) - 1], 16)},
    'qword_address': {'m': re.compile('QWORD PTR \[(rbp|rip|rdx)[+-]0x[0-9a-f]+\]'),
                      'c': lambda x: int(x[15:len(x) - 1], 16),
                      'get_reg': lambda x: x[11:14],
                      'get_sign': lambda x: x[14]},
    'rbp_address': {'m': re.compile('\[rbp-0x[0-9a-f]+\]'), 'c': lambda x: int(x[5:len(x) - 1], 16)},
    'rbp_address_trimmed': {'m': re.compile('rbp-0x[0-9a-f]+'), 'c': lambda x: int(x[4:], 16)},
    'relative_rbp_trimmed': {'m': re.compile('rbp-0x\d+'), 'c': lambda x: int(x[4:], 16)},
    'hex_num': {'m': re.compile('0x[0-9a-f]+'), 'c': lambda x: int(x, 16)}
}

dangerous_functions = ['<gets@plt>', '<strcpy@plt>', '<strcat@plt>',
                       '<fgets@plt>', '<strncpy@plt>', '<strncat@plt>']

registers = {'rax': '', 'rbx': '', 'rcx': '', 'rdx': '', 'rdi': '', 'rsi': '', 'r8': '', 'r9': '', 'r10': '',
             'r11': '', 'r12': '', 'r13': '', 'r14': '', 'r15': '', 'rbp': '', 'rsp': 0, 'rip': ''}
reg_names = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rbp',
             'rsp', 'rip']


class Register:
    name = ''
    # value inserted at beginning
    val = None
    # value in lower half
    e_val = None
    has_e_val = False

    def set_val(self, val: int, is_e_val: bool = False) -> None:
        if is_e_val:
            self.e_val = val
            self.has_e_val = True
        else:
            self.val = val

    def __init__(self, name: str, val: int = -1):
        self.name = name
        if name[0] == 'e':
            self.e_val = val
            self.has_e_val = True
        else:
            self.val = val

    def __repr__(self):
        if self.has_e_val:
            appendix = ' | ' + str(self.e_val)
        else:
            appendix = ''
        return "Register " + self.name + ':' + str(self.val) + appendix


class Segment:
    relative_to = 'rbp'
    bytes = 0
    val = None
    var = None

    def __init__(self, bytes, var: dict=None):
        if isinstance(bytes, int):
            self.bytes = bytes
        elif bytes == 'QWORD':
            self.bytes = 8
        elif bytes == 'DWORD':
            self.bytes = 4
        elif bytes == 'rbp':
            self.bytes = -8

        self.var = var

    def __repr__(self):
        if self.val:
            appendix = " with value " + str(self.val)
        else:
            appendix = ''
        return "Segment of " + str(self.bytes) + " bytes" + appendix


class State:
    """Describes the state of the program after execution of the instruction inst"""

    # current name of the function
    f_n = ''

    # the instruction
    inst = {}

    # if the instruction is a function call, this will be a list of the instruction of the functions called
    children = []

    # the register values at this point of the execution
    reg_vals = {}

    # the stack at this point of the execution
    stack = {}

    # if this is a call instruction, this is the name of the function that gets called
    # it exists just for convenience, so it doesn't have to be looked up from State.inst
    # and it provides an easy way of checking if the instruction is a call
    called_fn = ''

    def __repr__(self, indent: str = '') -> str:
        """Called by print, should print all info about the state"""
        s = indent + "Data of state. Current f_n: " + self.f_n
        s = s + "\n" + indent + "inst:"
        s = s + indent + pformat(self.inst)
        s = s + "\n" + indent + "called_fn: " + self.called_fn
        s = s + "\n" + indent + "reg_vals:"
        s = s + indent + pformat(self.reg_vals)
        s = s + "\n" + indent + "stack:"
        s = s + indent + pformat(self.stack)
        s = s + "\n" + indent + "children:\n"
        for child in self.children:
            s = s + child.__repr__(indent + "\t")
        s = s + indent + "end of state\n"
        return s

    def add_reg_val(self, inst: str, reg: str, val: str) -> None:
        """Adds to the registers of the current state the new value at register reg. How this is handled
        depends on the instruction inst, which is sub, mov or lea.
        """

        print('\n-----------------------', self.f_n)
        print(inst + " " + reg + " " + val)

        done = False
        the_reg = None

        if reg[0] == 'e':
            reg2 = 'r' + reg[1:]
            is_e = True
        else:
            reg2 = reg
            is_e = False

        if reg2 in reg_names:  # dest is a register

            if reg2 in self.reg_vals.keys(): # register already exists
                the_reg = self.reg_vals[reg2]
            else:
                the_reg = Register(reg)


            if val in reg_names:  # val is a register
                if inst == 'mov':
                    # put content of the register val into reg
                    the_reg = deepcopy(self.reg_vals[val])
                    the_reg.name = reg2
                    done = True

            elif reg_match['hex_num']['m'].match(val):  # val is a hex number
                # convert to int
                val = reg_match['hex_num']['c'](val)
                if inst == 'sub':
                    the_reg.set_val(val, is_e)
                    done = True
                elif inst == 'mov':
                    the_reg.set_val(val, is_e)
                    done = True

            elif reg_match['qword_address']['m'].match(val):  # value is qword memory
                offset = reg_match['qword_address']['c'](val)
                reg_new = reg_match['qword_address']['get_reg'](val)
                sign = reg_match['qword_address']['get_sign'](val)
                if sign == '-':
                    offset = -offset
                # load qword bytes from stack and put them in reg
                if offset in self.stack.keys():
                    print('value found, add code here')
                else:
                    print('value not found, add code here')

            elif reg_match['rbp_address']['m'].match(val):  # value is like [rbp-0x50]
                val = reg_match['rbp_address']['c'](val)
                if inst == 'mov':
                    # put into reg the next 64 bytes at memory -val
                    pass
                    #done = True
                elif inst == 'lea':
                    # put the address, that is the offset from rbp into the register
                    the_reg.set_val(-val, is_e)
                    done = True

        elif reg_match['dword_address']['m'].match(reg):  # register is memory, dword long
            # offset from rbp
            reg_offset = reg_match['dword_address']['c'](reg)
            if self.stack[-reg_offset]:  # there is something at that memory address
                if self.stack[-reg_offset].var:  # one of the local variables
                    if reg_match['hex_num']['m'].match(val):  # val is a hex number
                        # convert to int
                        val = reg_match['hex_num']['c'](val)
                        if self.stack[-reg_offset].bytes == 4:  # the value inserted is as long as the variable
                            self.stack[-reg_offset].val = val
                            done = True


        if done:
            # print("done")
            self.reg_vals[reg2] = the_reg
            print(self.stack)
            print(self.reg_vals)
        else:
            print(bcolors.FAIL)
            print("INSTRUCTION NOT ANALYZED")
            print(bcolors.ENDC)


def analyze_inst(inst: dict, f_n: str, append_to: list, prev_reg: list = []) -> list:
    """ Analyzes the instruction inst and creates a State object appended to append_to

    :param inst: An instruction as in the given JSON format
    :param f_n:  The name of the function this instruction is executed in
    :param append_to: The list of states the new state will be appended to
    :param prev_reg: The register values at the previous step of the program
    :return: The register values of the current/new state

    The prev_reg param, and return value are just for the recursive calls of the function.
    When called initially, append_to should be a global list like p
    """
    global dangerous_functions_occurring
    # pprint("analyzing")
    # pprint(inst)
    # print("in function", f_n)
    # pprint("parameter prev_reg:")
    # pprint(prev_reg)

    # Create the new state of this program
    s = State()
    s.f_n = f_n
    s.inst = inst
    # initialize with registers of previous state
    s.reg_vals = prev_reg[0]
    s.stack = prev_reg[1]
    s.children = []

    if inst['op'] in ['mov', 'lea', 'sub']:
        # these are the three operations in which register values change
        s.add_reg_val(inst['op'], inst['args']['dest'], inst['args']['value'])
    elif inst['op'] == 'call':
        # the instruction is a call to called_fn
        called_fn = inst['args']['fnname']
        # remove <,> of called_fn
        called_fn_trimmed = my_str_trim(called_fn)

        if called_fn_trimmed in data.keys():
            # in this case we're calling a user defined generic function

            # put that string into s
            s.called_fn = called_fn_trimmed

            # keeps track of the register values.
            use_reg_vals = [s.reg_vals, s.stack]
            for instr in data[called_fn_trimmed]['instructions']:
                # go through each instruction of the called function
                # analyze it, appending the new states to the children of the current state
                # also pass it a copy of the current register values
                # after each call it returns the register value after said call
                # so we pass that on to the next call
                use_reg_vals = analyze_inst(instr, called_fn_trimmed, s.children, deepcopy(use_reg_vals))
            # now use_reg_vals contains the register values after the function call, so we update our state
            [s.reg_vals, s.stack] = deepcopy(use_reg_vals)
        elif called_fn in dangerous_functions:
            # a call of one of the dangerous functions we consider
            # save that to the state so it doesn't need to be looked up in state.inst all the time
            s.called_fn = called_fn
            # add the current state to the list of dangerous functions occurring
            dangerous_functions_occurring.append(s)
    # after the state is completely analyzed (with all its children) we add it to append_to
    append_to.append(s)
    # pprint("returning reg_vals")
    # pprint(s.reg_vals)
    return [s.reg_vals, s.stack]


def add_variable_positions(var: dict, stack: dict) -> None:
    """Goes through all variables of all functions.

    Adds attribute rbp_distance to it, that is the decimal integer distance of the address of the variable to rbp"
    Adds/inititializes bytes_filled, which is updated, everytime some user function fills it

    {'address': 'rbp-0x50',
           'bytes': 64,
           'bytes_filled': 0,
           'name': 'buf',
           'rbp_distance': 80,
           'type': 'buffer'}
    """

    for f_n in var.keys():
        alloc = []
        for v in var[f_n]:
            v['bytes_filled'] = 0
            var_address = v['address']
            if reg_match['relative_rbp_trimmed']['m'].match(var_address):
                var_rbp_distance = reg_match['relative_rbp_trimmed']['c'](var_address)
                v['rbp_distance'] = var_rbp_distance
                alloc.append([v['rbp_distance'] - v['bytes'], v['rbp_distance']])
                stack[-var_rbp_distance] = Segment(v['bytes'], v)
            else:
                print('ERROR in add_variable_positions: value of variable_address does not match re, is', var_address)
        sorted(alloc, key=lambda pair: pair[0])
        for i in range(0, len(alloc) - 1):
            end_this = alloc[i][1]
            start_next = alloc[i + 1][0]
            if end_this < start_next:
                v = {
                    'address': 'rbp-' + hex(start_next),
                    'bytes': start_next - end_this,
                    'name': 'my_padding_var_' + str(i),
                    'rbp_distance': start_next,
                    'type': 'padding'
                }
                var[f_n].append(v)


def print_list():
    """utility method for printing the tree"""
    for s in p:
        print(s)


def process_json(the_data):
    global data, var, p
    data = the_data
    # pprint(data)

    # Get function names
    func_names = data.keys()

    stack = {'0': Segment('rbp')}

    # Parse vars and instrs for each function
    var = {}
    for f_n in func_names:
        var[f_n] = data[f_n]['variables']
    add_variable_positions(var, stack)

    # analyze all instructions of main
    reg = {'rbp': Register('rbp'), 'rsp': Register('rsp', 0)}
    prev_reg = [reg, stack]

    print(prev_reg)
    print(deepcopy(prev_reg))
    for inst in data['main']['instructions']:
        prev_reg = analyze_inst(inst, 'main', p, deepcopy(prev_reg))

    return [p, var, dangerous_functions_occurring]
