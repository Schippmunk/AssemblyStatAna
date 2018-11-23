from pprint import pprint
from pprint import pformat
from copy import deepcopy
from util import *

# the raw imported json file
data = {}

# the processed list of states
p = []

# the states of p containing a call to a dangerous function
dangerous_functions_occurring = []

# the variables declared in json, indexed by offset from rbp
variables = {}
var = {}

# the dangerous fuctions we consider
dangerous_functions = ['<gets@plt>', '<strcpy@plt>', '<strcat@plt>',
                       '<fgets@plt>', '<strncpy@plt>', '<strncat@plt>']

# the names of the registers used
reg_names = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rbp',
             'rsp', 'rip']


class Register:
    """Models a register

    Keeps track of its name and value, particularly if only parts of it such es eax instead of rax are read
    """

    # the name of the register, one of reg_names
    name = ''
    # the current value it holds
    val = None
    # value in lower half
    e_val = None
    # whether it has a value in the lower half
    has_e_val = False

    def set_val(self, val: int, is_e_val: bool = False) -> None:
        """Sets the value val, or just the lower have if is_e_val is true"""

        if is_e_val:
            self.e_val = val
            self.has_e_val = True
        else:
            self.val = val

    def get_val(self, is_e_val: bool = False) -> int:
        """Returns the value val or just the lower half of the register, if is_e_val is true"""

        if is_e_val:
            return self.e_val
        else:
            return self.val

    def __init__(self, name: str, val=None):
        """Constructor, does not require a value to be assigned and detects if just the lower half is used"""

        if name[0] == 'e':
            self.name = 'r' + name[1:]
            self.e_val = val
            self.has_e_val = True
        else:
            self.name = name
            self.val = val

    def __repr__(self) -> str:
        """Returns a string representation of the Register object, used by print"""

        if self.has_e_val:
            appendix = ' | ' + str(self.e_val)
        else:
            appendix = ''
        return "Reg " + self.name + ':' + str(self.val) + appendix


class Segment:
    """Models a Segment of memory in the stack."""

    # the register the offset is relative to. For now this is always rbp (of main)
    relative_to = 'rbp'
    # the amount of reserved bytes
    bytes = 0
    # the value stored at that location
    val = 0
    # the dictionary of the json of the variable of the program
    var = None

    def get_val(self) -> int:
        """Returns the value val"""

        return self.val

    def __init__(self, bytes, var: dict = None, val: int = 0):
        """Constructor.

        :param bytes: the size of the segment. Can be an integer or one of QWORD, DWORD, BYTE
        :param var: pass json of variable if it exists
        :param val: the initial value in that segment
        """

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

    def __repr__(self) -> str:
        """Returns a string representation of the Register object, used by print"""

        appendix = ''
        if self.val:
            appendix = " with value " + str(self.val)
        if self.var:
            appendix = appendix + " with " + str(self.var)
        return "Segment of " + str(self.bytes) + " bytes" + appendix


class Variable:
    """Models a variable of the C program, contains additional information to the json object"""

    # the attributes from the json object
    address = ''
    bytes = 0
    name = ''
    type = ''
    # the amount of bytes user input possibly filled this with. Used for strcat analysis
    bytes_filled = 0
    # the distance of the value from the rbp, also its address/key in our stack model
    rbp_distance = 0

    def fill(self, bytes: int) -> None:
        """Adds :param bytes: to bytes_filledf"""

        self.bytes_filled = self.bytes_filled + bytes

    def __init__(self, json_data: dict):
        self.address = json_data['address']
        self.bytes = json_data['bytes']
        self.name = json_data['name']
        self.type = json_data['type']

        # a matcher of adresses, together with handlers
        reg_match = {
            'relative_rbp_trimmed': {'m': re.compile('rbp-0x[0-9a-f]+'), 'c': lambda x: int(x[4:], 16)}
        }
        # use it to convert
        rbp_distance = reg_match['relative_rbp_trimmed']['c'](json_data['address'])
        self.rbp_distance = - rbp_distance
        self.bytes_filled = 0

    def __repr__(self):
        """Returns a string representation of the Register object, used by print"""

        return "Variable: " + self.name + " " + str(self.bytes) + " " + str(self.rbp_distance) + " " + self.type


class State:
    """Describes the state of the program after execution of the instruction inst"""

    # name of the function the instruction is in
    f_n = ''

    # the instruction
    inst = {}

    # if the instruction is a function call, this will be a list of the instruction of the functions called
    children = []

    # the register values after inst is executed
    reg_vals = {}

    # the stack after inst is executed
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
        """Returns the memory segment at address.

        Address is either an integer, and then this will look for address as a key in self.stack. If  address is a
        register, it uses the value of that register as key
        """
        if isinstance(address, int):
            return self.stack[address]
        elif at_e_val or isinstance(address, Register):
            return self.stack[address.get_val(at_e_val)]

    def add_seg(self, pos: int, seg: Segment) -> None:
        """Overrides stack at pos with seg"""

        self.stack[pos] = seg

    def get_reg_val(self, reg: str) -> Register:
        """Returns the register object at index reg"""

        if reg[0] == 'e':
            reg = 'r' + reg[1:]
        return self.reg_vals[reg]

    def get_address_type(self, address: str) -> dict:
        """Analyzes an address given in an assembly instruction, as dest or source"""

        if address[0] == 'B':
            # the address is of type BYTE PTR [rbp-0x...]
            block = {'type': 'mem', 'len': 'BYTE', 'relative': address[10:13], 'sign': address[13],
                     'val': int(address[14:len(address) - 1], 16)}
            return block

        elif address[0] in ['Q', 'D']:
            # the address is of type DWORD PTR [rbp-0x...]
            # or QWORD PTR [rbp-0x...]
            block = {'type': 'mem', 'len': address[:5], 'relative': address[11:14], 'sign': address[14],
                     'val': int(address[15:len(address) - 1], 16)}
            # Ignore those big offsets of rip, they were meaningless in all of our tests and are probably where
            # user input is initially stored in in the program
            if address[:17] == 'QWORD PTR [rip+0x':
                block['ignore'] = True
            else:
                block['ignore'] = False
            return block

        elif address[0] == '[':
            # address is of type [rbp-0x...]
            return {'type': 'mem', 'relative': address[1:4], 'sign': address[4],
                    'val': int(address[5:len(address) - 1], 16)}

        elif address[0] == '0':
            # the address is a hex number
            # convert it to int
            val = int(address, 16)
            return {'type': 'num', 'val': val}

        else:
            # the address is a register
            # address2 is the actual register, if address is of the form e.g. eax
            if address[0] == 'e':
                address2 = 'r' + address[1:]
                is_e = True
            else:
                address2 = address
                is_e = False

            if address2 in self.reg_vals.keys():
                # if there is already a register at address2 in this state return it
                return {'type': 'reg', 'reg': self.reg_vals[address2], 'is_e': is_e}
            else:
                # otherwise create a new Register instance and add it to reg_vals, return it
                the_reg = Register(address2)
                self.reg_vals[address2] = the_reg
                return {'type': 'reg', 'reg': the_reg, 'is_e': is_e}

    def memory_op(self, inst: str, dest: dict, src: dict) -> None:
        """Handles the assembly instructions inst = mov, lea, sub, with dest and src being return values of
        get_address_type
        """

        # print(dest)
        # print(src)
        # print('----- now analyzing')
        done = False
        if inst == 'sub':
            # handle sub instruction

            if dest['type'] == 'reg':
                # destination is a register

                if src['type'] == 'reg':
                    # source is a register, has not yet occurred
                    pass

                elif src['type'] == 'num':
                    # source is a hex number. convert it and update the destination register
                    val1 = self.get_reg_val(dest['reg'].name).get_val(dest['is_e'])
                    val2 = src['val']
                    dest['reg'].set_val(val1 - val2, dest['is_e'])
                    done = True

                elif src['type'] == 'mem':
                    # source is a memory address, has not yet occurred
                    pass

            elif dest['type'] == 'mem':
                # destination is a memory addres, has not yet occurred

                if src['type'] == 'reg':
                    pass
                elif src['type'] == 'num':
                    pass

        elif inst == 'lea':
            # load effective address, our address is the offset from rbp
            # src always memory, dest always register
            offset = src['val']
            self.reg_vals[dest['reg'].name].set_val(-offset)
            done = True

        elif inst == 'mov':
            # move instruction

            if dest['type'] == 'reg':
                # destination is a register

                if src['type'] == 'reg':
                    # source is a register
                    # create a deep copy of the source register, important not to just use the same mutable object
                    the_copy = deepcopy(src['reg'])
                    the_copy.name = dest['reg'].name
                    self.reg_vals[dest['reg'].name] = the_copy
                    done = True

                elif src['type'] == 'num':
                    # source is a hex number, just update the value
                    self.reg_vals[dest['reg'].name].set_val(src['val'], dest['is_e'])
                    done = True

                elif src['type'] == 'mem':
                    # source is a memory address

                    if src['ignore']:
                        done = True
                    else:
                        # one that is not on the list of ignored ones
                        # read the value and put it into the register
                        seg = self.get_seg(-src['val'])
                        self.reg_vals[dest['reg'].name].set_val(seg.val, dest['is_e'])
                        done = True

            elif dest['type'] == 'mem':
                # destination is a memory address
                if src['type'] == 'reg':
                    # source is a register, does not occur in basic tests
                    pass
                elif src['type'] == 'num':
                    # source is a hex number that will be used as a memory address
                    offset = dest['val']
                    if -offset in self.stack.keys():
                        existing_segment = self.get_seg(-offset)
                        existing_segment.val = src['val']
                        done = True

        # print("Stack now")
        # print(self.stack)
        # print("Reg now")
        # print(self.reg_vals)
        if not done:
            pass
            # print("---------------------------")
            # print(inst)
            # print(dest)
            # print(src)
            # print(bcolors.FAIL)
            # print("INSTRUCTION NOT ANALYZED")
            # print(bcolors.ENDC)

    def add_reg_val(self, inst: str, reg: str, val: str) -> None:
        """Adds to the registers of the current state the new value at register reg. How this is handled
        depends on the instruction inst, which is sub, mov or lea.
        """

        dest = self.get_address_type(reg)
        src = self.get_address_type(val)

        self.memory_op(inst, dest, src)


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
    """Fills the global variable variables and sorts it"""

    global variables
    for f_n in data.keys():
        variables[f_n] = {}
        for v in data[f_n]['variables']:
            v = Variable(v)
            stack[v.rbp_distance] = Segment(v.bytes, v)
            variables[f_n][v.rbp_distance] = v


def print_list():
    """utility method for printing the tree"""

    for s in p:
        print(s)


def process_json(the_data):
    """Starts the analysis. Sets global vars and calls analysis functions with initial values"""
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
