import re

import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks executing as root"
    tags = ["COMMAND_MAYBE_SYSTEM"]
    def analyze(self) -> None:
        # Searching checking root or not:

        regex_excluded_class_names = re.compile(STR_REGEXP_TYPE_EXCLUDE_CLASSES)
        found_strings = []

        for string_analysis in self.analysis.find_strings(r"^(su\b|sudo |/system/bin)"):
            if not all([regex_excluded_class_names.match(xref_class.name)
                        for xref_class, xref_method in string_analysis.get_xref_from()]):
                found_strings.append(string_analysis)

        if found_strings:
            self.writer.startWriter("COMMAND_MAYBE_SYSTEM", LEVEL_NOTICE, "Executing \"root\" or System Privilege Checking",
                               "The app may has the code checking for \"root\" permission, mounting filesystem operations or monitoring system:",
                               ["Command"])
            for found_string in found_strings:
                self.writer.write(found_string.get_value())
                self._print_xrefs(found_string)
        else:

            self.writer.startWriter("COMMAND_MAYBE_SYSTEM", LEVEL_INFO, "Executing \"root\" or System Privilege Checking",
                               "Did not find codes checking \"root\" permission(su) or getting system permission (It's still possible we did not find out).",
                               ["Command"])

