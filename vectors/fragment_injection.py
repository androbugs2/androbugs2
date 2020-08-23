import re

import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks severe fragment injection vulnerability prior to Android 4.4 (API 19)."
    tags = ["FRAGMENT_INJECTION"]

    def analyze(self) -> None:
        # Android Fragment Vulnerability (prior to Android 4.4)

        prog = re.compile("Landroid/support/v(\d*)/app/Fragment;")
        REGEXP_EXCLUDE_CLASSESd_fragment_class = re.compile("(Landroid/support/)|(Lcom/actionbarsherlock/)")
        list_Fragment = []

        for dalvik in self.dalvik:
            for cls in dalvik.get_classes():
                if (cls.get_superclassname() == "Landroid/app/Fragment;") or prog.match(cls.get_superclassname()):
                    if not REGEXP_EXCLUDE_CLASSESd_fragment_class.match(cls.get_name()):
                        # Exclude the classes from library itself to make the finding more precise and to check the user really use fragment, not just include the libs
                        list_Fragment.append(cls.get_name())



        list_Fragment_vulnerability_NonMethod_classes = []
        list_Fragment_vulnerability_Method_OnlyReturnTrue_methods = []
        list_Fragment_vulnerability_Method_NoIfOrSwitch_methods = []
        list_Fragment = self.filtering_engine.filter_list_of_classes(list_Fragment)

        if list_Fragment:
            for dalvik in self.dalvik:
                for cls in dalvik.get_classes():
                    if (cls.get_superclassname() == "Landroid/preference/PreferenceActivity;") or (
                            cls.get_superclassname() == "Lcom/actionbarsherlock/app/SherlockPreferenceActivity;"):
                        boolHas_isValidFragment = False
                        method_isValidFragment = None
                        for method in cls.get_methods():
                            if (method.get_name() == "isValidFragment") and (
                                    method.get_descriptor() == "(Ljava/lang/String;)Z"):
                                boolHas_isValidFragment = True
                                method_isValidFragment = method
                                break
                        if boolHas_isValidFragment:
                            register_analyzer = staticDVM.RegisterAnalyzerVMImmediateValue(
                                method_isValidFragment.get_instructions())
                            if register_analyzer.get_ins_return_boolean_value():
                                list_Fragment_vulnerability_Method_OnlyReturnTrue_methods.append(method_isValidFragment)
                            else:
                                if not register_analyzer.has_if_or_switch_instructions():  # do not have "if" or "switch" op in instructions of method
                                    list_Fragment_vulnerability_Method_NoIfOrSwitch_methods.append(method_isValidFragment)
                        else:
                            list_Fragment_vulnerability_NonMethod_classes.append(cls.get_name())

        list_Fragment_vulnerability_NonMethod_classes = self.filtering_engine.filter_list_of_classes(
            list_Fragment_vulnerability_NonMethod_classes)
        list_Fragment_vulnerability_Method_OnlyReturnTrue_methods = self.filtering_engine.filter_list_of_methods(
            list_Fragment_vulnerability_Method_OnlyReturnTrue_methods)
        list_Fragment_vulnerability_Method_NoIfOrSwitch_methods = self.filtering_engine.filter_list_of_methods(
            list_Fragment_vulnerability_Method_NoIfOrSwitch_methods)

        if list_Fragment_vulnerability_NonMethod_classes or list_Fragment_vulnerability_Method_OnlyReturnTrue_methods or list_Fragment_vulnerability_Method_NoIfOrSwitch_methods:

            output_string = """'Fragment' or 'Fragment for ActionbarSherlock' has a severe vulnerability prior to Android 4.4 (API 19). 
        Please check: 
        (1)http://developer.android.com/reference/android/os/Build.VERSION_CODES.html#KITKAT 
        (2)http://developer.android.com/reference/android/preference/PreferenceActivity.html#isValidFragment(java.lang.String) 
        (3)http://stackoverflow.com/questions/19973034/isvalidfragment-android-api-19 
        (4)http://securityintelligence.com/new-vulnerability-android-framework-fragment-injection/ 
        (5)http://securityintelligence.com/wp-content/uploads/2013/12/android-collapses-into-fragments.pdf 
        (6)https://cureblog.de/2013/11/cve-2013-6271-remove-device-locks-from-android-phone/ """

            self.writer.startWriter("FRAGMENT_INJECTION", LEVEL_CRITICAL, "Fragment Vulnerability Checking", output_string,
                               None, "BID 64208, CVE-2013-6271")

            if list_Fragment_vulnerability_NonMethod_classes:
                if self.int_target_sdk >= 19:
                    # You must override. Otherwise, it always throws Exception
                    self.writer.write(
                        "You MUST override 'isValidFragment' method in every \"PreferenceActivity\" class to avoid Exception throwing in Android 4.4:")
                    for i in list_Fragment_vulnerability_NonMethod_classes:  # Notice: Each element in the list is NOT method, but String
                        self.writer.write("    " + i)
                else:
                    # You must override. Otherwise, it always throws Exception
                    self.writer.write(
                        "These \"PreferenceActivity\" classes may be vulnerable because they do not override 'isValidFragment' method (If you do not load any fragment in the PreferenceActivity, please still override 'isValidFragment' method and only return \"false\" to secure your app in the future changes) :")
                    for i in list_Fragment_vulnerability_NonMethod_classes:  # Notice: Each element in the list is NOT method, but String
                        self.writer.write("    " + i)

            if list_Fragment_vulnerability_Method_OnlyReturnTrue_methods:
                self.writer.write(
                    "You override 'isValidFragment' and only return \"true\" in those classes. You should use \"if\" condition to check whether the fragment is valid:")
                self.writer.write(
                    "(Example code: http://stackoverflow.com/questions/19973034/isvalidfragment-android-api-19/20139823#20139823)")
                for method in list_Fragment_vulnerability_Method_OnlyReturnTrue_methods:
                    self.writer.write("    %s-> %s%s" % (method.get_class_name(), method.get_name(), method.get_descriptor()))

            if list_Fragment_vulnerability_Method_NoIfOrSwitch_methods:
                self.writer.write(
                    "Please make sure you check the valid fragment inside the overridden 'isValidFragment' method:")
                for method in list_Fragment_vulnerability_Method_NoIfOrSwitch_methods:
                    self.writer.write("    %s-> %s%s" % (method.get_class_name(), method.get_name(), method.get_descriptor()))

            if list_Fragment:
                self.writer.write("All of the potential vulnerable \"fragment\":")
                for i in list_Fragment:
                    self.writer.write("    " + i)

        else:
            self.writer.startWriter("FRAGMENT_INJECTION", LEVEL_INFO, "Fragment Vulnerability Checking",
                               "Did not detect the vulnerability of \"Fragment\" dynamically loading into \"PreferenceActivity\" or \"SherlockPreferenceActivity\"",
                               None, "BID 64208, CVE-2013-6271")
