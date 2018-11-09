import json
from pprint import pprint


def parser(name):
    global data
    with open(name) as f:
        data = json.load(f)
    
    return parse_json(data)

def parse_json(data):

    func_vars =  {}
    func_instrs = {}
    func_Ninstr = {}
    result = {}

    #Get function names
    func_names = data.keys() 
    
    #Parse vars and instrs for each function
    for f_n in func_names:
        func_vars[f_n]=data[f_n]['variables']
        func_instrs[f_n]=data[f_n]['instructions']
        func_Ninstr[f_n] = data[f_n]['Ninstructions']

    func_instrs['main'] = func_instrs['main'][3:]

    result['func_vars'] = func_vars

    pprint(result['func_vars'])
    result['func_instrs'] = func_instrs
    result['func_Ninstr'] = func_Ninstr
    
    
    return result


    
    
    