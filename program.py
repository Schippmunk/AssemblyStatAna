from pprint import pprint
from pprint import pformat
from util import *
from vuln_checker import dangerous_functions
from vuln_checker import dangerous_functions_occuring


data = {}
p = []


class State:
    # current name of the function
    f_n = ''
    # the instruction
    inst = {}
    # if the instruction is a function call, this will be a list of the instruction of the functions called
    children = []
    # the register values at this point of the execution
    reg_vals = {}

    def __repr__(self, indent=''):
        s = indent + "Data of state. Current function: " + self.f_n
        s = s + "\n" + indent + "Instruction:"
        s = s + indent + pformat(self.inst)
        s = s + "\n" + indent + "reg_vals:"
        s = s + indent + pformat(self.reg_vals)
        s = s + "\n" + indent + "children:\n"
        for child in self.children:
            s = s + child.__repr__(indent + "\t")
        s = s + indent + "end of state\n"
        return s

    def add_reg_val(self, reg, val):
        self.reg_vals[reg] = val




def analyze_inst(inst, f_n, append_to, prev_reg = {}):
    if not prev_reg:
        if p:
            prev_reg = p[-1].reg_vals.copy()

    s = State()
    s.f_n = f_n
    s.inst = inst
    s.reg_vals = prev_reg
    s.children = []

    if inst['op'] in ['mov', 'lea', 'sub']:
        s.add_reg_val(inst['args']['dest'], inst['args']['value'])
    elif inst['op'] == 'call':
        called_fn = inst['args']['fnname']
        # remove <,>
        called_fn_trimmed = my_str_trim(called_fn)
        if called_fn_trimmed in data.keys():
            # in this case we're calling a user defined generic function
            new_reg_vals = {}
            for instr in data[called_fn_trimmed]['instructions']:
                new_reg_vals = analyze_inst(instr, called_fn_trimmed, s.children, s.reg_vals.copy())
            s.reg_vals = new_reg_vals.copy()
        elif called_fn in dangerous_functions.keys():
            dangerous_functions_occuring.append(s)
    append_to.append(s)
    return s.reg_vals



def print_list():
    for s in p:
        print(s)


def process_json(the_data):
    global data
    global p
    data = the_data
    for inst in data['main']['instructions']:
        analyze_inst(inst, 'main', p)

    print_list()
    return p

