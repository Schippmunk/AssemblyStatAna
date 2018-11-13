from pprint import pprint
from pprint import pformat
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
reg_names = registers.keys()


class State:
    """Describes the state of the program after execution of the instruction inst"""

    # current name of the function
    f_n = ''

    # the instruction
    inst = {}

    # if the instruction is a function call, this will be a list of the instruction of the functions called
    children = []

    # the register values at this point of the execution
    # [value, type, from register]
    # value is an integer. if type = a (address) it describes the offset from register
    # if type = v (value) it is just a value. in that case register=None
    # if key=rbp, reg denotes the name of the function of which it is the rbp
    reg_vals = {'rsp': {'val': 0, 'typ': 'a', 'reg': 'rbp'}, 'rbp': {'val': 0, 'typ': 'a', 'reg': 'main'}}

    # the stack at this point of the execution
    stack = {'0': {'len': '-8'}}

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
        s = s + "\n" + indent + "children:\n"
        for child in self.children:
            s = s + child.__repr__(indent + "\t")
        s = s + indent + "end of state\n"
        return s

    def add_reg_val(self, inst: str, reg: str, val: str) -> None:
        """Adds to the registers of the current state the new value at register reg. How this is handled
        depends on the instruction inst, which is sub, mov or lea.

        TODO: Look at the different ways of moving data between memory and registers, as recommended in project.
        This is necessary here, if we want to implmement generic function calls, or programs with a more complex main fn
        """
        print('\n-----------------------', self.f_n)
        print(inst + " " + reg + " " + val)
        done = False
        if reg[0] == 'e':
            print('converted inst to')
            reg = 'r' + reg[1:]
            print(inst + " " + reg + " " + val)
        if reg in reg_names:  # dest is a register
            if reg not in self.reg_vals.keys():
                self.reg_vals[reg] = {}
            if val in reg_names:  # val is a register
                if inst == 'mov':
                    # put content of the register val into reg
                    self.reg_vals[reg] = self.reg_vals[val]
                    done = True
            elif reg_match['hex_num']['m'].match(val):  # val is a hex number
                # convert to int
                val = reg_match['hex_num']['c'](val)
                if inst == 'sub':
                    self.reg_vals[reg]['val'] = self.reg_vals[reg]['val'] - val
                    done = True
                elif inst == 'mov':
                    self.reg_vals[reg]['val'] = val
                    self.reg_vals[reg]['typ'] = 'v'
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
                    print('value not found')
                    self.reg_vals[reg]['val'] = 'QWORD'
                    self.reg_vals[reg]['typ'] = 'v'
                    self.reg_vals[reg]['reg'] = val[10:]
                done = True
                pass
            elif reg_match['rbp_address']['m'].match(val):  # value is like [rbp-0x50]
                val = reg_match['rbp_address']['c'](val)
                #print(val)
                if inst == 'mov':
                    # put into reg the next 8 bytes at memory -val
                    done = True
                    pass
                elif inst == 'lea':
                    # put the address, that is the offset from rbp into the register
                    self.reg_vals[reg]['val'] = -val
                    self.reg_vals[reg]['typ'] = 'a'
                    self.reg_vals[reg]['reg'] = 'rbp'
                    done = True
        elif reg_match['dword_address']['m'].match(reg):  # register is memory, dword long
            # offset from rbp
            reg_offset = reg_match['dword_address']['c'](reg)
            if self.stack[-reg_offset]:  # there is something at that memory address
                if self.stack[-reg_offset]['name']:  # one of the local variables
                    if reg_match['hex_num']['m'].match(val):  # val is a hex number
                        # convert to int
                        val = reg_match['hex_num']['c'](val)
                        if self.stack[-reg_offset]['bytes'] == 4:  # the value inserted is as long as the variable
                            self.stack[-reg_offset]['val'] = val
                            done = True
        if done:
            print("done")
            #print(self.stack)
            #print(self.reg_vals)
        else:
            print(bcolors.FAIL)
            print("INSTRUCTION NOT ANALYZED")
            print(bcolors.ENDC)


def analyze_inst(inst: dict, f_n: str, append_to: list, prev_reg: dict = {}) -> dict:
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
                use_reg_vals = analyze_inst(instr, called_fn_trimmed, s.children, use_reg_vals.copy())
            # now use_reg_vals contains the register values after the function call, so we update our state
            [s.reg_vals, s.stack] = use_reg_vals.copy()
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
                stack[-var_rbp_distance] = v
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

    stack = {'0': {'len': '-8', 'val': 'rbp_main'}}

    # Parse vars and instrs for each function
    var = {}
    for f_n in func_names:
        var[f_n] = data[f_n]['variables']
    add_variable_positions(var, stack)

    # analyze all instructions of main
    prev_reg = [{'rsp': {'val': 0, 'typ': 'a', 'reg': 'rbp'}, 'rbp': {'val': 0, 'typ': 'a', 'reg': 'main'}}, stack]

    for inst in data['main']['instructions']:
        prev_reg = analyze_inst(inst, 'main', p, prev_reg.copy())

    return [p, var, dangerous_functions_occurring]
