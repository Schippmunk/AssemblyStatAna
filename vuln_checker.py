from parser import *

#basic, for now
dangerous_functions = ['<gets@plt>', '<strcpy@plt>', '<strcat@plt>', '<fgets@plt>', '<strncpy@plt>', '<strncat@plt>']


def check_buffer_vuln(p_data):


    func_names = p_data['func_vars'].keys() 
    print(func_names)
    func_instrs = p_data['func_instrs']
    
    dangerous_calls = []

    for f_n in func_names:
        print(f_n)
        for instr in func_instrs[f_n]:
            if instr['op'] == 'call':
                if instr['args']['fnname'] in dangerous_functions:
                    dangerous_calls.append(instr)

    return dangerous_calls


def check_vuln(p_data):
    dangerous_calls = check_buffer_vuln(p_data)

    print(dangerous_calls)
    #check_dangerous_func()


def main(name):

    p_data = parser(name)

    check_vuln(p_data)    
    '''if (not check_buffer_exists()):
        print("No buffers found in this file! :-)")
        return False'''

if __name__ == "__main__":
    import sys
    main("public_tests/test" + sys.argv[1] + ".json")
    
    
    
   