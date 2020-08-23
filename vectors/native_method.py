import collections

import helper_functions
from vector_base import VectorBase
from constants import *
from engines import *

class Vector(VectorBase):
    description = "get native methods and frameworks"
    tags = ["NATIVE_METHODS", "NATIVE_LIBS_LOADING"]

    def analyze(self) -> None:
        """
            Example:
                const-string v0, "AndroBugsNdk"
                invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
        """

        dic_ndk_library_classname_to_ndkso_mapping = {}
        list_ndk_library_classname_to_ndkso_mapping = []
        path_ndk_library_classname_to_ndkso_mapping = self.analysis.find_methods("Ljava/lang/System;", "loadLibrary",
                                                                                 "\(Ljava/lang/String;\)V")
        for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(path_ndk_library_classname_to_ndkso_mapping):
            if (i.getResult()[0] is None) or (not i.is_string(0)):
                continue
            path = i.getPath()['src_method']
            src_class_name = path.get_class_name()
            if src_class_name is None:
                continue
            if src_class_name not in dic_ndk_library_classname_to_ndkso_mapping:
                dic_ndk_library_classname_to_ndkso_mapping[src_class_name] = []

            dic_ndk_library_classname_to_ndkso_mapping[src_class_name].append(helper_functions.toNdkFileFormat(str(i.getResult()[0])))
            list_ndk_library_classname_to_ndkso_mapping.append([helper_functions.toNdkFileFormat(str(i.getResult()[0])), i.getPath()])

        if list_ndk_library_classname_to_ndkso_mapping:
            self.writer.startWriter("NATIVE_LIBS_LOADING", LEVEL_NOTICE, "Native Library Loading Checking",
                               "Native library loading codes(System.loadLibrary(...)) found:")

            for ndk_location, path in list_ndk_library_classname_to_ndkso_mapping:
                self.writer.write("[" + ndk_location + "]")
                self.writer.show_Path(path)
        else:
            self.writer.startWriter("NATIVE_LIBS_LOADING", LEVEL_INFO, "Native Library Loading Checking",
                               "No native library loaded.")

        dic_native_methods = {}
        for dalvik in self.dalvik:
            for method in dalvik.get_methods():
                # checks if method is native
                if 0x100 & method.get_access_flags():
                    class_name = method.get_class_name()
                    if self.filtering_engine.is_class_name_not_in_exclusion(class_name):
                        if class_name not in dic_native_methods:
                            dic_native_methods[class_name] = []
                        dic_native_methods[class_name].append(method)

        if dic_native_methods:

            if self.args.extra == 2:  # The output may be too verbose, so make it an option

                dic_native_methods_sorted = collections.OrderedDict(sorted(dic_native_methods.items()))

                self.writer.startWriter("NATIVE_METHODS", LEVEL_NOTICE, "Native Methods Checking", "Native methods found:")

                for class_name, method_names in list(dic_native_methods_sorted.items()):
                    if class_name in dic_ndk_library_classname_to_ndkso_mapping:
                        self.writer.write("Class: %s (Loaded NDK files: %s)" % (
                            class_name, dic_ndk_library_classname_to_ndkso_mapping[class_name]))
                    else:
                        self.writer.write("Class: %s" % class_name)
                    self.writer.write("   ->Methods:")
                    for method in method_names:
                        self.writer.write("        %s%s" % (method.get_name(), method.get_descriptor()))

        else:
            if self.args.extra == 2:  # The output may be too verbose, so make it an option
                self.writer.startWriter("NATIVE_METHODS", LEVEL_INFO, "Native Methods Checking", "No native method found.")
