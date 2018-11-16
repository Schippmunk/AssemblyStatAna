import json
import util
from pprint import pprint
import os
import fnmatch

inputfilename = ''
outputfilename = ''
vulnerabilities = []


def parser(name):
    """Opens JSON file and calls parse_json with it"""

    global inputfilename

    pattern = "*" + name + "*.json"

    for file in os.listdir('./public_tests'):
        # match test number + .json, and not output.json
        if fnmatch.fnmatch(file, pattern) and (not fnmatch.fnmatch(file, "*output.json")):
            inputfilename = "public_tests/" + file
            break

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

    f = open(outputfilename, "w+")


def add_vulnerability(vulnerability):
    """Appends the vulnerability to filename name"""

    util.prin("Adding the following vulnerability to " + outputfilename)
    print(util.bcolors.OKGREEN)
    pprint(vulnerability)
    print(util.bcolors.ENDC)
    vulnerabilities.append(vulnerability)


def create_vulnerability(vulnerability='', vuln_function='', fn_name='', overflow_var='', address='', overflown_var='',
                         overflown_address=''):
    """Produces a dictionary in the desired output format"""

    vuln = {
        'vulnerability': vulnerability,
        'vuln_function': vuln_function,
        'fnname': fn_name,
        'overflow_var': overflow_var,
        'address': address}
    if vulnerability not in ['RBPOVERFLOW', 'INVALIDACCS', 'SCORRUPTION', 'RETOVERFLOW']:
        vuln['overflown_var'] = overflown_var
    elif vulnerability in ['INVALIDACCS', 'SCORRUPTION']:
        vuln['overflown_address'] = overflown_address

    return vuln


def write_json():
    f = open(outputfilename, "a")
    # f.write(str(vulnerability))
    json.dump(vulnerabilities, f, indent=4)
    f.write("\n")
    f.close()
