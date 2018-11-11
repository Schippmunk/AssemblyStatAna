from pprint import pprint
from pprint import pformat
from util import *
from vuln_checker import dangerous_functions

# the raw imported json file
data = {}
# the processed list of states
p = []
# the states of p containing a call to a dangerous function
dangerous_functions_occurring = []


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
        if inst == 'sub':
            val = reg + "-" + str(val)
        elif inst == 'mov':
            pass
        elif inst == 'lea':
            pass
        if val in self.reg_vals.keys():
            # in this case, val is another register which we know the value of, so we use that value instead
            val = self.reg_vals[val]

        self.reg_vals[reg] = val


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
    #pprint("analyzing")
    #pprint(inst)
    #print("in function", f_n)
    #pprint("parameter prev_reg:")
    #pprint(prev_reg)

    # Create the new state of this program
    s = State()
    s.f_n = f_n
    s.inst = inst
    # initialize with registers of previous state
    s.reg_vals = prev_reg
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
            use_reg_vals = s.reg_vals
            for instr in data[called_fn_trimmed]['instructions']:
                # go through each instruction of the called function
                # analyze it, appending the new states to the children of the current state
                # also pass it a copy of the current register values
                # after each call it returns the register value after said call
                # so we pass that on to the next call
                use_reg_vals = analyze_inst(instr, called_fn_trimmed, s.children, use_reg_vals.copy())
            # now use_reg_vals contains the register values after the function call, so we update our state
            s.reg_vals = use_reg_vals.copy()
        elif called_fn in dangerous_functions.keys():
            # a call of one of the dangerous functions we consider
            # save that to the state so it doesn't need to be looked up in state.inst all the time
            s.called_fn = called_fn
            # add the current state to the list of dangerous functions occurring
            dangerous_functions_occurring.append(s)
    # after the state is completely analyzed (with all its children) we add it to append_to
    append_to.append(s)
    #pprint("returning reg_vals")
    #pprint(s.reg_vals)
    return s.reg_vals


def print_list():
    """utility method for printing the tree"""
    for s in p:
        print(s)


def process_json(the_data):
    global data
    global p
    data = the_data
    prev_reg = {}
    for inst in data['main']['instructions']:
        prev_reg = analyze_inst(inst, 'main', p, prev_reg.copy())

    return [p, dangerous_functions_occurring]
