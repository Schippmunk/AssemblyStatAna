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
var = {}
variables = {}

reg_match = {
    'dword_address': {'m': re.compile('DWORD PTR \[(rbp|rip)[+-]0x[0-9a-f]+\]'),
                      'c': lambda x: int(x[15:len(x) - 1], 16)},
    'qword_address': {'m': re.compile('QWORD PTR \[(rbp|rip|rdx)[+-]0x[0-9a-f]+\]'),
                      'c': lambda x: int(x[15:len(x) - 1], 16),
                      'get_reg': lambda x: x[11:14],
                      'get_sign': lambda x: x[14]},
    'byte_address': {'m': re.compile('BYTE PTR \[(rbp|rip|rdx)[+-]0x[0-9a-f]+\]'),
                     'c': lambda x: int(x[14:len(x) - 1], 16),
                     'get_reg': lambda x: x[10:13],
                     'get_sign': lambda x: x[13]},
    'rbp_address': {'m': re.compile('\[rbp-0x[0-9a-f]+\]'), 'c': lambda x: int(x[5:len(x) - 1], 16)},
    'rbp_address_trimmed': {'m': re.compile('rbp-0x[0-9a-f]+'), 'c': lambda x: int(x[4:], 16)},
    'relative_rbp_trimmed': {'m': re.compile('rbp-0x[0-9a-f]+'), 'c': lambda x: int(x[4:], 16)},
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

    def get_val(self, is_e_val: bool = False) -> int:
        if is_e_val:
            return self.e_val
        else:
            return self.val

    def __init__(self, name: str, val=None):
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
    val = 0
    var = None

    def get_val(self):
        return self.val

    def __init__(self, bytes, var: dict = None, val: int = 0):
        if isinstance(bytes, int):
            self.bytes = bytes
        elif bytes == 'QWORD':
            self.bytes = 8
        elif bytes == 'DWORD':
            self.bytes = 4
        elif bytes == 'BYTE':
            self.bytes = 1
        elif bytes == 'rbp':
            self.bytes = -8

        self.var = var
        self.val = val

    def __repr__(self):
        appendix = ''
        if self.val:
            appendix = " with value " + str(self.val)
        if self.var:
            appendix = appendix + " with " + str(self.var)
        return "Segment of " + str(self.bytes) + " bytes" + appendix


class Variable:
    address = ''
    bytes = 0
    bytes_filled = 0
    name = ''
    rbp_distance = 0
    type = ''

    def fill(self, bytes: int) -> None:
        self.bytes_filled = self.bytes_filled + bytes

    def __repr__(self):
        return "Variable: " + self.name + " " + str(self.bytes) + " " + str(self.rbp_distance) + " " + self.type

    def __init__(self, json_data: dict):
        self.address = json_data['address']
        self.bytes = json_data['bytes']
        self.name = json_data['name']
        self.type = json_data['type']

        rbp_distance = reg_match['relative_rbp_trimmed']['c'](json_data['address'])
        self.rbp_distance = - rbp_distance
        self.bytes_filled = 0


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

    def get_seg(self, address, at_e_val: bool = False) -> Segment:
        if isinstance(address, int):
            return self.stack[address]
        elif at_e_val or isinstance(address, Register):
            return self.stack[address.get_val(at_e_val)]

    def add_seg(self, pos: int, seg: Segment) -> None:
        self.stack[pos] = seg

    def get_reg_val(self, reg: str) -> Register:
        if reg[0] == 'e':
            reg = 'r' + reg[1:]
        return self.reg_vals[reg]

    def get_address_type(self, address: str) -> dict:
        if address[0] == 'B':
            block = {'type': 'mem', 'len': 'BYTE', 'relative': address[10:13], 'sign': address[13],
                     'val': int(address[14:len(address) - 1], 16)}
            return block
        elif address[0] in ['Q', 'D']:
            block = {'type': 'mem', 'len': address[:5], 'relative': address[11:14], 'sign': address[14],
                     'val': int(address[15:len(address) - 1], 16)}
            if address[:17] == 'QWORD PTR [rip+0x':
                block['ignore'] = True
            else:
                block['ignore'] = False
            return block
        elif address[0] == '[':
            return {'type': 'mem', 'relative': address[1:4], 'sign': address[4],
                    'val': int(address[5:len(address) - 1], 16)}
        elif address[0] == '0':
            val = int(address, 16)
            return {'type': 'num', 'val': val}
        else:
            if address[0] == 'e':
                address2 = 'r' + address[1:]
                is_e = True
            else:
                address2 = address
                is_e = False

            if address2 in self.reg_vals.keys():
                return {'type': 'reg', 'reg': self.reg_vals[address2], 'is_e': is_e}
            else:
                the_reg = Register(address2)
                self.reg_vals[address2] = the_reg
                return {'type': 'reg', 'reg': the_reg, 'is_e': is_e}

    def memory_op(self, inst: str, dest: dict, src: dict) -> None:
        #print(dest)
        #print(src)
        #print('----- now analyzing')
        done = False
        if inst == 'sub':
            if dest['type'] == 'reg':
                if src['type'] == 'reg':
                    pass
                elif src['type'] == 'num':
                    val1 = self.get_reg_val(dest['reg'].name).get_val(dest['is_e'])
                    val2 = src['val']
                    dest['reg'].set_val(val1 - val2, dest['is_e'])
                    done = True
                elif src['type'] == 'mem':
                    pass
            elif dest['type'] == 'mem':
                if src['type'] == 'reg':
                    pass
                elif src['type'] == 'num':
                    pass
        elif inst == 'lea':
            # src always memory, dest always register
            offset = src['val']
            self.reg_vals[dest['reg'].name].set_val(-offset)
            done = True
        elif inst == 'mov':
            if dest['type'] == 'reg':
                if src['type'] == 'reg':
                    the_copy = deepcopy(src['reg'])
                    the_copy.name = dest['reg'].name
                    self.reg_vals[dest['reg'].name] = the_copy
                    done = True
                elif src['type'] == 'num':
                    self.reg_vals[dest['reg'].name].set_val(src['val'], dest['is_e'])
                    done = True
                elif src['type'] == 'mem':
                    if src['ignore']:
                        done = True
                    else:
                        seg = self.get_seg(-src['val'])
                        self.reg_vals[dest['reg'].name].set_val(seg.val, dest['is_e'])
                        done = True

            elif dest['type'] == 'mem':
                if src['type'] == 'reg':
                    pass
                elif src['type'] == 'num':
                    offset = dest['val']
                    if -offset in self.stack.keys():
                        existing_segment = self.get_seg(-offset)
                        existing_segment.val = src['val']
                        done = True

        #print("Stack now")
        #print(self.stack)
        #print("Reg now")
        #print(self.reg_vals)
        if not done:
            return
#            print("---------------------------")
#            print(inst)
#            print(dest)
#            print(src)
#            print(bcolors.FAIL)
#            print("INSTRUCTION NOT ANALYZED")
#            print(bcolors.ENDC)

    def add_reg_val(self, inst: str, reg: str, val: str) -> None:
        """Adds to the registers of the current state the new value at register reg. How this is handled
        depends on the instruction inst, which is sub, mov or lea.
        """
        #print('\n-----------------------', self.f_n)
        #print(inst + " " + reg + " " + val)

        dest = self.get_address_type(reg)
        src = self.get_address_type(val)

        self.memory_op(inst, dest, src)

        """   elif reg_match['qword_address']['m'].match(val):  # value is qword memory
                if not val[
                       :17] == 'QWORD PTR [rip+0x':  # exclude those strange QWORD things, I think they're user input
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
                else:
                    done = Trueval[
                       :17] == 'QWORD PTR [rip+0x'

            elif reg_match['rbp_address']['m'].match(val):  # value is like [rbp-0x50]
                val = reg_match['rbp_address']['c'](val)
                if inst == 'mov':
                    # put into reg the next 64 bytes at memory -val
                    pass
                    # done = True
                elif inst == 'lea':
                    # put the address, that is the offset from rbp into the register
                    the_reg.set_val(-val, is_e)
                    done = True

        elif reg_match['dword_address']['m'].match(reg):  # register is memory, dword long
            # offset from rbp
            reg_offset = reg_match['dword_address']['c'](reg)
            if -reg_offset in self.stack.keys():  # there is something at that memory address
                if self.stack[-reg_offset].var:  # one of the local variables
                    if reg_match['hex_num']['m'].match(val):  # val is a hex number
                        # convert to int
                        val = reg_match['hex_num']['c'](val)
                        if self.stack[-reg_offset].bytes == 4:  # the value inserted is as long as the variable
                            self.stack[-reg_offset].val = val
                            done = True
        elif reg_match['qword_address']['m'].match(reg):  # register is memory, dword long
            # offset from rbp
            print(self.stack)
            print(self.reg_vals)
            reg_offset = reg_match['qword_address']['c'](reg)
            if -reg_offset in self.stack.keys():  # there is something at that memory address
                if self.stack[-reg_offset].var:  # one of the local variables
                    # val is a hex number
                    # has not occurred yet
                    if reg_match['hex_num']['m'].match(val):
                        # convert to int
                        val = reg_match['hex_num']['c'](val)
                        # the value inserted is as long as the variable
                        if self.stack[-reg_offset].bytes == 8:
                            self.stack[-reg_offset].val = val
                            done = True
        elif reg_match['byte_address']['m'].match(reg): # register is memory, byte long
            reg_offset = reg_match['byte_address']['c'](reg)
            if -reg_offset in self.stack.keys():  # there is something at that memory address
               pass
            else:
                if reg_match['hex_num']['m'].match(val):  # val is a hex number
                    # convert to int
                    val = reg_match['hex_num']['c'](val)
                    seg = Segment('BYTE', val=val)
                    self.add_seg(-reg_offset, seg)
                    done = True"""


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
    return [s.reg_vals, s.stack]


def add_variable_positions(stack: dict) -> None:
    global variables
    for f_n in data.keys():
        variables[f_n] = {}
        for v in data[f_n]['variables']:
            v = Variable(v)
            stack[v.rbp_distance] = Segment(v.bytes, v)
            variables[f_n][v.rbp_distance] = v
    sorted(variables)


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
    # Parse vars and instrs for each function
    for f_n in func_names:
        var[f_n] = data[f_n]['variables']

    # initialize the stack
    stack = {0: Segment('rbp')}

    add_variable_positions(stack)

    # initialize the registers
    reg = {'rbp': Register('rbp'), 'rsp': Register('rsp', 0)}
    prev_reg = [reg, stack]

    # analyze the program
    for inst in data['main']['instructions']:
        prev_reg = analyze_inst(inst, 'main', p, deepcopy(prev_reg))
