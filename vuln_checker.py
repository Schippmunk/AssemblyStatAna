from parser import *

p_data = {}

def check_gets(f_n, instruction):  
    print(instruction)    

def check_strcpy(f_n, instruction): 
    print(instruction)

def check_strcat(f_n, instruction): 
    print(instruction)

def check_fgets(f_n, instruction): 
    print(f_n)
    print(instruction)
    #print(get_var(f_n, 28381))

def check_strncpy(f_n, instruction): 
    print(instruction)

def check_strncat(f_n, instruction): 
    print(instruction)




def get_var(f_n, address):
    for var in p_data[f_n]['variables']:
        if var['address'] == address:
            return var
    print("get_var ERROR: No such address {} in function {}".format(address, f_n))





#basic, for now
dangerous_functions = {'<gets@plt>': check_gets, '<strcpy@plt>': check_strcpy, '<strcat@plt>': check_strcat, '<fgets@plt>': check_fgets, '<strncpy@plt>': check_strncpy, '<strncat@plt>': check_strncat}

def check_buffer_vuln():

    for f_n in p_data.keys():
        print(f_n)
        for instr in p_data[f_n]['instructions']:
            if instr['op'] == 'call':
                if instr['args']['fnname'] in dangerous_functions:
                    dangerous_functions[instr['args']['fnname']](f_n, instr)



def check_vuln():
    check_buffer_vuln()

    #check_dangerous_func()


def main(name):

    global p_data
    p_data = parser(name)

    check_vuln()    
    '''if (not check_buffer_exists()):
        print("No buffers found in this file! :-)")
        return False'''

if __name__ == "__main__":
    import sys
    main("public_tests/test" + sys.argv[1] + ".json")
    
    
    
   