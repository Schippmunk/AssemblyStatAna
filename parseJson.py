import json
from pprint import pprint

data = {}
func_vars =  {}
func_instrs = {}
func_Ninstr = {}

def main(name):
    open_json(name)
    parse_json()

def open_json(name):
    global data
    with open(name) as f:
        data = json.load(f)
    
    return True

def parse_json():
    #Get function names
    func_names = data.keys() 
    
    global func_vars
    global func_instrs
    global func_Ninstr
    
    #Parse vars and instrs for each function
    for f_n in func_names:
        print(f_n)
        func_vars[f_n]=data[f_n]['variables']
        func_instrs[f_n]=data[f_n]['instructions']
        func_Ninstr[f_n] = data[f_n]['Ninstructions']
        
    print("Vars:\n")
    pprint(func_vars)
    print("\n")
    print("Instrs:\n")
    pprint(func_instrs)
    print("\n")
    print("N_Instrs:\n")
    pprint(func_Ninstr)
    
    return True

if __name__ == "__main__":
    import sys
    main("public_tests/test" + sys.argv[1] + ".json")