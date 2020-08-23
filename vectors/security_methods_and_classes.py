from vector_base import VectorBase
from constants import *
import re

class Vector(VectorBase):
    description = "Checks if there are any security related method and class names present"
    tags = ["Security_Methods", "Security_Classes"]
    def analyze(self) -> None:

        regexGerneralRestricted = ".*(config|setting|constant).*"
        regexSecurityRestricted = ".*(encrypt|decrypt|encod|decod|aes|sha1|sha256|sha512|md5).*"  # No need to add "sha1" and "des"
        # show the user which package is excluded

        prog = re.compile(regexGerneralRestricted, re.I)
        prog_sec = re.compile(regexSecurityRestricted, re.I)

        # Security methods finding:

        if self.args.extra == 2:  # The output may be too verbose, so make it an option

            list_security_related_methods = []

            for dalvik in self.dalvik:
                for method in dalvik.get_methods():
                    if prog.match(method.get_name()) or prog_sec.match(method.get_name()):
                        if self.filtering_engine.is_class_name_not_in_exclusion(method.get_class_name()):
                            # Need to exclude "onConfigurationChanged (Landroid/content/res/Configuration;)V"
                            if (method.get_name() != 'onConfigurationChanged') and (
                                    method.get_descriptor() != '(Landroid/content/res/Configuration;)V'):
                                list_security_related_methods.append(method)

            if list_security_related_methods:
                self.writer.startWriter("Security_Methods", LEVEL_NOTICE, "Security Methods Checking",
                                   "Find some security-related method names:")
                for method in list_security_related_methods:
                    self.writer.write(method.get_class_name() + "->" + method.get_name() + method.get_descriptor())
            else:
                self.writer.startWriter("Security_Methods", LEVEL_INFO, "Security Methods Checking",
                                   "Did not detect method names containing security related string.")

        if self.args.extra == 2:  # The output may be too verbose, so make it an option
            list_security_related_classes = []

            for dalvik in self.dalvik:
                for current_class in dalvik.get_classes():
                    if prog.match(current_class.get_name()) or prog_sec.match(current_class.get_name()):
                        if self.filtering_engine.is_class_name_not_in_exclusion(current_class.get_name()):
                            list_security_related_classes.append(current_class)

            if list_security_related_classes:
                self.writer.startWriter("Security_Classes", LEVEL_NOTICE, "Security Classes Checking",
                                   "Find some security-related class names:")

                for current_class in list_security_related_classes:
                    self.writer.write(current_class.get_name())
            else:
                self.writer.startWriter("Security_Classes", LEVEL_INFO, "Security Classes Checking",
                                   "Did not detect class names containing security related string.")
