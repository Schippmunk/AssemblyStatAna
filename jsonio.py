import json
from pprint import pprint

inputfilename = ''
outputfilename = ''


def parser(name):
    """Opens JSON file and calls parse_json with it"""

    global inputfilename
    inputfilename = "public_tests/test" + name + ".json";
    global outputfilename
    outputfilename = "public_tests/test" + name + ".OURoutput.json"

    try:
        with open(inputfilename) as f:
            data = json.load(f)
    except FileNotFoundError:
        print("No such file or directory:", inputfilename)
        return None
    create_output_file()

    return parse_json(data)


def parse_json(data):
    """Creates a dictionary of the JSON data and returns it

    keys are function names
    each value is a dictionary with keys instructions, Ninstructions and variables
    """
    result = {}

    # Get function names
    func_names = data.keys()

    # Parse vars and instrs for each function
    for f_n in func_names:
        result[f_n] = {'instructions': data[f_n]['instructions'], 'Ninstructions': data[f_n]['Ninstructions'],
                       'variables': data[f_n]['variables']}

    for f_n in func_names:
        result[f_n]['instructions'] = result[f_n]['instructions']

    # result['main'] = func_instrs['main'][3:]
    # pprint(result)
    return result


def create_output_file():
    """Creates the output file with filename outputfilename"""
    #TODO: actually create the file
    pass

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
def add_vulnerability(vulnerability):
    """Appends the vulnerability to filename name

    vulnerability is a dictionary such as
        "overflown_address": "rbp-0x10",
        "fnname": "fgets",
        "vuln_function": "main",
        "address": "400539",
        "vulnerability": "INVALIDACCS",
        "overflow_var": "buf"
    """
    print(bcolors.GREEN)
    print("Adding the following vulnerability to ", outputfilename)
    pprint(vulnerability)
    print(bcolors.ENDC)
    #TODO: actually add it to the file


def create_vulnerability(vulnerability='', vuln_function='', fnname='', overflow_var='', address='', overflown_var=''):
    """Produces a dictionary in the desired output format"""
    vuln = {
        'vulnerability': vulnerability,
        'fnname': fnname,
        'address': address,
        'overflow_var': overflow_var,
        'vuln_function': vuln_function}
    if not vulnerability == 'RBPOVERFLOW':
        vuln['overflown_var'] = overflown_var
    return vuln
