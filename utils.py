import re


def is_success_base64_decoded_string(base64_string):
    # Punct: \:;/-.,?=<>+_()[]{}|"'~`*
    return re.match('^[A-Za-z0-9\\\:\;\/\-\.\,\?\=\<\>\+\_\(\)\[\]\{\}\|\"\'\~\`\*\ ]+$', base64_string)


def is_null_or_empty_string(input_string, strip_whitespaces=False):
    if input_string is None:
        return True
    if strip_whitespaces:
        if input_string.strip() == "":
            return True
    else:
        if input_string == "":
            return True
    return False


def is_base64(base64_string):
    return re.match('^[A-Za-z0-9+/]+[=]{0,2}$', base64_string)

def get_elements_by_tagname(xml, tagname):
    results = []
    get_elements_by_tagname_sub(xml, tagname, results)
    return results

def get_elements_by_tagname_sub(xml, tagname, results):

    children = xml.getchildren()

    for child in children:
        get_elements_by_tagname_sub(child, tagname, results)

    if xml.tag == tagname:
        results.append(xml)
