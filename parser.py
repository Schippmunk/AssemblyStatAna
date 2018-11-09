import json
from pprint import pprint


def parser(name):
    """Opens JSON file and calls parse_json with it"""
    with open(name) as f:
        data = json.load(f)
    
    return parse_json(data)

def parse_json(data):
    """Creates a dictionary of the JSON data and returns it

    keys are function names
    each value is a dictionary with keys instructions, Ninstructions and variables
    """
    result = {}

    #Get function names
    func_names = data.keys() 
    
    #Parse vars and instrs for each function
    for f_n in func_names:
        result[f_n] = {'instructions': data[f_n]['instructions'], 'Ninstructions': data[f_n]['Ninstructions'], 'variables': data[f_n]['variables']}

    for f_n in func_names:
        result[f_n]['instructions'] = result[f_n]['instructions'][3:]
    
    #result['main'] = func_instrs['main'][3:]
    #pprint(result)
    return result


    
    
    