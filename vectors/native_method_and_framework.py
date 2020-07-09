import collections

import helper_functions
from vector_base import VectorBase
from constants import *
from engines import *

class Vector(VectorBase):
    description = "get native methods and frameworks"

    def analyze(self) -> None:
        """
            Example:
                const-string v0, "AndroBugsNdk"
                invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
        """

        cm = self.dalvik.get_class_manager()

        dic_ndk_library_classname_to_ndkso_mapping = {}
        list_ndk_library_classname_to_ndkso_mapping = []
        path_ndk_library_classname_to_ndkso_mapping = self.analysis.find_methods(
            "Ljava/lang/System;", "loadLibrary", "(Ljava/lang/String;)V")
        path_ndk_library_classname_to_ndkso_mapping = self.filtering_engine.filter_list_of_paths(self.dalvik,
                                                                                           path_ndk_library_classname_to_ndkso_mapping)
        for i in staticDVM.trace_register_value_by_param_in_source_paths(self.dalvik, self.analysis, path_ndk_library_classname_to_ndkso_mapping):
            if (i.getResult()[0] is None) or (not i.is_string(0)):
                continue
            so_file_name = i.getResult()[0]
            src_class_name, src_method_name, src_descriptor = i.getPath().get_src(cm)
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
                self.writer.show_Path(self.dalvik, path)
        else:
            self.writer.startWriter("NATIVE_LIBS_LOADING", LEVEL_INFO, "Native Library Loading Checking",
                               "No native library loaded.")

        dic_native_methods = {}
        for method in self.dalvik.get_methods():
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

        # Framework Detection: Bangcle

        is_using_framework_bangcle = False
        is_using_framework_ijiami = False
        is_using_framework_mono_droid = False

        # Display only when using the Framework (Notice: This vector depends on "List all native method")
        if list_ndk_library_classname_to_ndkso_mapping:

            list_ndk_library_classname_to_ndkso_mapping_only_ndk_location = helper_functions.dump_NDK_library_classname_to_ndkso_mapping_ndk_location_list(
                list_ndk_library_classname_to_ndkso_mapping)

            if "libsecexe.so" in list_ndk_library_classname_to_ndkso_mapping_only_ndk_location:
                path_secapk = self.analysis.find_methods("Lcom/secapk/wrapper/ACall;",
                                                         "getACall",
                                                         "()Lcom/secapk/wrapper/ACall;")
                if path_secapk:
                    is_using_framework_bangcle = True

            if len(list_ndk_library_classname_to_ndkso_mapping_only_ndk_location) == 2:
                if ("libexec.so" in list_ndk_library_classname_to_ndkso_mapping_only_ndk_location) and (
                        "libexecmain.so" in list_ndk_library_classname_to_ndkso_mapping_only_ndk_location):
                    paths_ijiami_signature = self.analysis.find_methods(
                        "Lcom/shell/NativeApplication;", "load", "(Landroid/app/Application; Ljava/lang/String;)Z")
                    if paths_ijiami_signature:
                        is_using_framework_ijiami = True

            # TODO replace with Noam's function
            # if (android_name_in_application_tag == "mono.android.app.Application"):
            #     for name, _, _ in self.apk.get_files_information():
            #         if (name == "lib/armeabi-v7a/libmonodroid.so") or (name == "lib/armeabi/libmonodroid.so"):
            #             is_using_Framework_MonoDroid = True
            #             break

            if is_using_framework_bangcle:
                self.writer.startWriter("FRAMEWORK_BANGCLE", LEVEL_NOTICE, "Encryption Framework - Bangcle",
                                   "This app is using Bangcle Encryption Framework (http://www.bangcle.com/). Please send your unencrypted apk instead so that we can check thoroughly.",
                                   ["Framework"])
            if is_using_framework_ijiami:
                self.writer.startWriter("FRAMEWORK_IJIAMI", LEVEL_NOTICE, "Encryption Framework - Ijiami",
                                   "This app is using Ijiami Encryption Framework (http://www.ijiami.cn/). Please send your unencrypted apk instead so that we can check thoroughly.",
                                   ["Framework"])

        if is_using_framework_mono_droid:
            self.writer.startWriter("FRAMEWORK_MONODROID", LEVEL_NOTICE, "Framework - MonoDroid",
                               "This app is using MonoDroid Framework (http://xamarin.com/android).", ["Framework"])
        else:
            self.writer.startWriter("FRAMEWORK_MONODROID", LEVEL_INFO, "Framework - MonoDroid",
                               "This app is NOT using MonoDroid Framework (http://xamarin.com/android).", ["Framework"])
