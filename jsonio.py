import json
import util
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

    return data


def parser_path(path: str) -> dict:
    """Opens JSON file and calls parse_json with it"""

    global inputfilename
    inputfilename = path
    global outputfilename
    outputfilename = path[:len(path) - 4] + "OURoutput.json"

    try:
        with open(inputfilename) as f:
            data = json.load(f)
    except FileNotFoundError:
        print("No such file or directory:", inputfilename)
        return None
    create_output_file()

    return parse_json(data)


def parse_json(data):
    result = {'data': data, 'vars': {}}

    # Get function names
    func_names = data.keys()

    # Parse vars and instrs for each function
    for f_n in func_names:
        result['vars'][f_n] = data[f_n]['variables']
    return result


def create_output_file():
    """Creates the output file with filename outputfilename"""
    # TODO: actually create the file
    pass


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
    util.prin("Adding the following vulnerability to " + outputfilename)
    print(util.bcolors.OKGREEN)
    pprint(vulnerability)
    print(util.bcolors.ENDC)
    # TODO: actually add it to the file


def create_vulnerability(vulnerability='', vuln_function='', fn_name='', overflow_var='', address='', overflown_var='',
                         overflown_address=''):
    """Produces a dictionary in the desired output format"""

    vuln = {
        'vulnerability': vulnerability,
        'vuln_function': vuln_function,
        'fnname': fn_name,
        'overflow_var': overflow_var,
        'address': address}
    if vulnerability not in ['RBPOVERFLOW', 'INVALIDACCS']:
        vuln['overflown_var'] = overflown_var
    if vulnerability == 'INVALIDACCS':
        vuln['overflown_address'] = overflown_address

    return vuln
