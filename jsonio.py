import json

inputfilename = ''
outputfilename = ''
vulnerabilities = []


def parser(name: str) -> dict:
    """Opens JSON file and calls parse_json with it"""

    global inputfilename
    inputfilename = name

    global outputfilename
    outputfilename = name[:len(name) - 4] + "output.json"

    try:
        with open(inputfilename) as f:
            data = json.load(f)
    except FileNotFoundError:
        print("No such file or directory:", inputfilename)
        return None
    create_output_file()

    return data


def parse_json(data: dict) -> dict:
    result = {'data': data, 'vars': {}}

    # Get function names
    func_names = data.keys()

    # Parse vars and instrs for each function
    for f_n in func_names:
        result['vars'][f_n] = data[f_n]['variables']
    return result


def create_output_file() -> None:
    """Creates the output file with filename outputfilename"""

    f = open(outputfilename, "w+")


def add_vulnerability(vulnerability: dict) -> None:
    """Appends the vulnerability to filename name"""

    # util.prin("Adding the following vulnerability to " + outputfilename)
    vulnerabilities.append(vulnerability)


def create_vulnerability(vulnerability: str = '', vuln_function: str = '', fn_name: str = '', overflow_var: str = '',
                         address: str = '', overflown_var: str = '',
                         overflown_address: str = '') -> dict:
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


def write_json() -> None:
    f = open(outputfilename, "a")
    # f.write(str(vulnerability))
    json.dump(vulnerabilities, f, indent=4)
    f.close()
