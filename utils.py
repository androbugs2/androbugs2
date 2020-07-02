import re


def is_success_base64_decoded_string(base64_string):
    # Punct: \:;/-.,?=<>+_()[]{}|"'~`*
    return re.match('^[A-Za-z0-9\\\:\;\/\-\.\,\?\=\<\>\+\_\(\)\[\]\{\}\|\"\'\~\`\*]+$', base64_string)


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


def is_base_64(base64_string):
    return re.match('^[A-Za-z0-9+/]+[=]{0,2}$', base64_string)
