import os
from textwrap import TextWrapper  # for indent in output
from androguard.core.analysis import analysis
import collections  # for sorting key of dictionary
from constants import *

REPORT_OUTPUT = 'print_and_file'  # when compiling to Windows executable, switch to "file"
DIRECTORY_REPORT_OUTPUT = "Reports/"  # Only need to specify when (REPORT_OUTPUT = TYPE_REPORT_OUTPUT_ONLY_FILE) or (REPORT_OUTPUT = TYPE_REPORT_OUTPUT_PRINT_AND_FILE)


class Writer:
    def __init__(self):
        self.__package_information = {}
        self.__cache_output_detail_stream = []
        self.__output_dict_vector_result_information = {}  # Store the result information (key: tag ; value: information_for_each_vector)
        self.__output_current_tag = ""  # The current vector analyzed

        self.__file_io_result_output_list = []  # Analyze vector result (for more convenient to save in disk)
        self.__file_io_information_output_list = []  # Analyze header result (include package_name, md5, sha1, etc.)

    def simplifyClassPath(self, class_name):
        if class_name.startswith('L') and class_name.endswith(';'):
            return class_name[1:-1]
        return class_name

    def show_xrefs_method_class_analysis_list(self, method_class_analysis_list, indention_space_count=0):
        for method_class_analysis in method_class_analysis_list:
            self.show_xrefs_method_class_analysis(method_class_analysis, indention_space_count)

    def show_xrefs_method_class_analysis(self, method_class_analysis, indention_space_count=0):

        dest_class_name = method_class_analysis.get_method().get_class_name()
        dest_name = method_class_analysis.get_method().get_name()
        dest_descriptor = method_class_analysis.get_method().get_descriptor()
        for __, source_method, idx in method_class_analysis.get_xref_from():

            self.write("=> %s->%s%s (0x%x) ---> %s->%s%s" % (source_method.get_class_name(),
                                                             source_method.get_name(),
                                                             source_method.get_descriptor(),
                                                             idx,
                                                             dest_class_name,
                                                             dest_name,
                                                             dest_descriptor),
                       indention_space_count)

    def show_xrefs_class_analysis_list(self, class_analysis_list, indention_space_count=0):
        for class_analysis in class_analysis_list:
            self.show_xrefs_class_analysis(class_analysis, indention_space_count)

    def show_xrefs_class_analysis(self, class_analysis, indention_space_count=0):

        dest_class_name = class_analysis.name
        for source_class, source_methods in class_analysis.get_xref_from().items():
            self.write("=> %s ---> %s" % (source_class.name, dest_class_name), indention_space_count)

    def show_Path(self, path, indention_space_count=0):
        """
			Different from analysis.show_Path, this "show_Path" writes to the tmp writer
		"""

        self.write("=> %s->%s%s (0x%x) ---> %s->%s%s" % (path['src_method'].get_class_name(),
                                                         path['src_method'].get_name(),
                                                         path['src_method'].get_descriptor(),
                                                         path['idx'],
                                                         path['dst_method'].get_class_name(),
                                                         path['dst_method'].get_name(),
                                                         path['dst_method'].get_descriptor()),
                   indention_space_count)

    def show_Path_only_source(self, vm, path, indention_space_count=0):
        self.write("=> %s->%s%s" % (path['src_method'].get_class_name(),
                                    path['src_method'].get_name(),
                                    path['src_method'].get_descriptor()), indention_space_count)

    def show_Paths(self, paths, indention_space_count=0):
        """
			Show paths of packages
			:param paths: a list of :class:`PathP` objects

			Different from "analysis.show_Paths", this "show_Paths" writes to the tmp writer
		"""
        for path in paths:
            self.show_Path(path, indention_space_count)


    def startWriter(self, tag, level, summary, title_msg, special_tag=None, cve_number=""):
        """
			"tag" is for internal usage
			"level, summary, title_msg, special_tag, cve_number" will be shown to the users
			It will be sorted by the "tag". The result will be sorted by the "tag".

			Notice: the type of "special_tag" is "list"
		"""
        self.completeWriter()
        self.__output_current_tag = tag

        assert ((tag is not None) and (level is not None) and (summary is not None) and (
                title_msg is not None)), "\"tag\", \"level\", \"summary\", \"title_msg\" should all have it's value."

        if tag not in self.__output_dict_vector_result_information:
            self.__output_dict_vector_result_information[tag] = []

        dict_tmp_information = dict()
        dict_tmp_information["level"] = level
        dict_tmp_information["title"] = title_msg.rstrip('\n')
        dict_tmp_information["summary"] = summary.rstrip('\n')
        dict_tmp_information["count"] = 0
        if special_tag:
            assert isinstance(special_tag, list), "Tag [" + tag + "] : special_tag should be list"
            dict_tmp_information["special_tag"] = special_tag  # Notice: the type of "special_tag" is "list"
        if cve_number:
            assert isinstance(cve_number, str), "Tag [" + tag + "] : special_tag should be string"
            dict_tmp_information["cve_number"] = cve_number

        self.__output_dict_vector_result_information[tag] = dict_tmp_information

    def get_valid_encoding_utf8_string(self, utf8_string):
        """
			unicode-escape: http://stackoverflow.com/questions/4004431/text-with-unicode-escape-sequences-to-unicode-in-python
			Encoding and Decoding:
				http://blog.wahahajk.com/2009/08/unicodedecodeerror-ascii-codec-cant.html
				http://www.evanjones.ca/python-utf8.html
				http://www.jb51.net/article/26543.htm
				http://www.jb51.net/article/17560.htm
		"""
        return utf8_string.decode('unicode_escape').encode('utf8')

    def write(self, detail_msg, indention_space_count=0):
        self.__cache_output_detail_stream.append(detail_msg + "\n")

    def get_packed_analyzed_results_for_mongodb(self):
        # For external storage

        analyze_packed_result = self.getInf()

        if analyze_packed_result:
            if self.get_analyze_status() == "success":
                analyze_packed_result["details"] = self.__output_dict_vector_result_information
            return analyze_packed_result

        return None

    def get_search_enhanced_packed_analyzed_results_for_mongodb(self):
        # For external storage

        analyze_packed_result = self.getInf()

        if analyze_packed_result:
            if self.get_analyze_status() == "success":

                prepared_search_enhanced_result = []

                for tag, dict_information in list(self.__output_dict_vector_result_information.items()):

                    search_enhanced_result = dict()

                    search_enhanced_result["vector"] = tag
                    search_enhanced_result["level"] = dict_information["level"]
                    search_enhanced_result["analyze_engine_build"] = analyze_packed_result["analyze_engine_build"]
                    search_enhanced_result["analyze_mode"] = analyze_packed_result["analyze_mode"]
                    if "analyze_tag" in analyze_packed_result:
                        search_enhanced_result["analyze_tag"] = analyze_packed_result["analyze_tag"]
                    search_enhanced_result["package_name"] = analyze_packed_result["package_name"]
                    if "package_version_code" in analyze_packed_result:
                        search_enhanced_result["package_version_code"] = analyze_packed_result["package_version_code"]
                    search_enhanced_result["file_sha512"] = analyze_packed_result["file_sha512"]
                    search_enhanced_result["signature_unique_analyze"] = analyze_packed_result[
                        "signature_unique_analyze"]

                    prepared_search_enhanced_result.append(search_enhanced_result)

                return prepared_search_enhanced_result

        return None

    def getInf(self, key=None, default_value=None):
        if key is None:
            return self.__package_information

        if key in self.__package_information:
            value = self.__package_information[key]
            if (value is None) and (
                    default_value is not None):  # [Important] if default_value="", the result of the condition is "False"
                return default_value
            return value

        # not found
        if default_value:  # [Important] if default_value="", the result of the condition is "False"
            return default_value

        return None

    def writePlainInf(self, msg):
        # if DEBUG :
        print((str(msg)))
        # [Recorded here]
        self.__file_io_information_output_list.append(str(msg))

    def writeInf(self, key, value, extra_title, extra_print_original_title=False):
        # if DEBUG :
        if extra_print_original_title:
            print((str(extra_title)))
            # [Recorded here]
            self.__file_io_information_output_list.append(str(extra_title))
        else:
            print((extra_title + ": " + str(value)))
            # [Recorded here]
            self.__file_io_information_output_list.append(extra_title + ": " + str(value))

        self.__package_information[key] = value

    def writeInf_ForceNoPrint(self, key, value):
        self.__package_information[key] = value

    def update_analyze_status(self, status):
        self.writeInf_ForceNoPrint("analyze_status", status)

    def get_analyze_status(self):
        return self.getInf("analyze_status")

    def get_total_vector_count(self):
        if self.__output_dict_vector_result_information:
            return len(self.__output_dict_vector_result_information)
        return 0

    def completeWriter(self):
        # save to DB
        if (self.__cache_output_detail_stream) and (self.__output_current_tag != ""):
            # This is the preferred way if you know that your variable is a string. If your variable could also be some other type then you should use myString == ""

            current_tag = self.__output_current_tag
            # try :
            if current_tag in self.__output_dict_vector_result_information:
                self.__output_dict_vector_result_information[current_tag]["count"] = len(
                    self.__cache_output_detail_stream)

                """
					Use xxx.encode('string_escape') to avoid translating user code into command
					For example: regex in the code of users' applications may include "\n" but you should escape it.

					I add "str(xxx)" because the "xxx" of xxx.encode should be string but "line" is not string.
					Now the title and detail of the vectors are escaped(\n,...), so you need to use "get_valid_encoding_utf8_string"

					[String Escape Example] 
					http://stackoverflow.com/questions/6867588/how-to-convert-escaped-characters-in-python
					>>> escaped_str = 'One \\\'example\\\''
					>>> print escaped_str.encode('string_escape')
					One \\\'example\\\'
					>>> print escaped_str.decode('string_escape')
					One 'example'
				"""

                output_string = ""
                for line in self.__cache_output_detail_stream:
                    output_string = output_string + str(
                        line)  # To escape the "\n" shown in the original string inside the APK

                self.__output_dict_vector_result_information[current_tag]["vector_details"] = output_string
                try:
                    self.__output_dict_vector_result_information[current_tag][
                        "title"] = self.__output_dict_vector_result_information[current_tag]["title"]
                except KeyError:
                    if DEBUG:
                        print("[KeyError on \"self.__output_dict_vector_result_information\"]")
                    pass

        self.__output_current_tag = ""
        self.__cache_output_detail_stream[:] = []  # Clear the items in the list

    def is_dict_information_has_cve_number(self, dict_information):
        if dict_information:
            if "cve_number" in dict_information:
                return True
        return False

    def is_dict_information_has_special_tag(self, dict_information):
        if dict_information:
            if "special_tag" in dict_information:
                if dict_information["special_tag"]:
                    return True
        return False

    def __sort_by_level(key, value):
        try:
            level = value[1]["level"]

            if level == LEVEL_CRITICAL:
                return 5
            elif level == LEVEL_WARNING:
                return 4
            elif level == LEVEL_NOTICE:
                return 3
            elif level == LEVEL_INFO:
                return 2
            else:
                return 1
        except KeyError:
            return 1

    def append_to_file_io_information_output_list(self, line):
        # Only write to the header of the "external" file
        self.__file_io_information_output_list.append(line)

    def save_result_to_file(self, output_file_path, args):
        if not self.__file_io_result_output_list:
            self.load_to_output_list(args)

        try:
            with open(output_file_path, "w") as f:
                if self.__file_io_information_output_list:
                    for line in self.__file_io_information_output_list:
                        f.write(line + "\n")
                for line in self.__file_io_result_output_list:
                    f.write(line + "\n")

            print(("<<< Analysis report is generated: " + os.path.abspath(output_file_path) + " >>>"))
            print("")

            return True
        except IOError as err:
            if DEBUG:
                print("[Error on writing output file to disk]")
            return False

    def show(self, args):
        if not self.__file_io_result_output_list:
            self.load_to_output_list(args)

        if self.__file_io_result_output_list:
            for line in self.__file_io_result_output_list:
                print(line)

    def output(self, line):  # Store here for later use on "print()" or "with ... open ..."
        # [Recorded here]
        self.__file_io_result_output_list.append(line)

    def output_and_force_print_console(self, line):  # Store here for later use on "print()" or "with ... open ..."
        # [Recorded here]
        self.__file_io_result_output_list.append(line)
        print(line)

    def load_to_output_list(self, args):
        """
			tag => dict(level, title_msg, special_tag, cve_number)
			tag => list(detail output)

			print(self.__output_dict_vector_result_information)
			print(self.__output_dict_vector_result_information["vector_details"])

			Example output:
				{'WEBVIEW_RCE': {'special_tag': ['WebView', 'Remote Code Execution'], 'title': "...", 'cve_number': 'CVE-2013-4710', 'level': 'critical'}}
				"Lcom/android/mail/ui/ConversationViewFragment;->onCreateView(Landroid/view/LayoutInflater; Landroid/view/ViewGroup;
					Landroid/os/Bundle;)Landroid/view/View; (0xa4) ---> Lcom/android/mail/browse/ConversationWebView;->addJavascriptInterface(Ljava/lang/Object; Ljava/lang/String;)V"

			"vector_details" is a detail string of a vector separated by "\n" controlled by the users

		"""

        self.__file_io_result_output_list[:] = []  # clear the list

        wrapperTitle = TextWrapper(initial_indent=' ' * 11, subsequent_indent=' ' * 11,
                                   width=args.line_max_output_characters)
        wrapperDetail = TextWrapper(initial_indent=' ' * 15, subsequent_indent=' ' * 20,
                                    width=args.line_max_output_characters)

        sorted_output_dict_result_information = collections.OrderedDict(
            sorted(self.__output_dict_vector_result_information.items()))  # Sort the dictionary by key

        for tag, dict_information in sorted(list(sorted_output_dict_result_information.items()),
                                            key=self.__sort_by_level,
                                            reverse=True):  # Output the sorted dictionary by level
            extra_field = ""
            if self.is_dict_information_has_special_tag(dict_information):
                for i in dict_information["special_tag"]:
                    extra_field += ("<" + i + ">")
            if self.is_dict_information_has_cve_number(dict_information):
                extra_field += ("<#" + dict_information["cve_number"] + "#>")

            if args.show_vector_id:
                self.output("[%s] %s %s (Vector ID: %s):" % (
                    dict_information["level"], extra_field, dict_information["summary"], tag))
            else:
                self.output("[%s] %s %s:" % (dict_information["level"], extra_field, dict_information["summary"]))

            for line in dict_information["title"].split('\n'):
                self.output(wrapperTitle.fill(line))

            if "vector_details" in dict_information:
                for line in dict_information["vector_details"].split('\n'):
                    self.output(wrapperDetail.fill(line))

        self.output("------------------------------------------------------------")

        stopwatch_total_elapsed_time = self.getInf("time_total")
        stopwatch_analyze_time = self.getInf("time_analyze")
        stopwatch_hacker_debuggable = self.getInf("time_hacker_debuggable_check")
        if stopwatch_total_elapsed_time and stopwatch_analyze_time:

            if (REPORT_OUTPUT == "file"):
                self.output_and_force_print_console(
                    "AndroBugs analyzing time: " + str(stopwatch_analyze_time) + " secs")
                self.output_and_force_print_console(
                    "HACKER_DEBUGGABLE_CHECK elapsed time: " + str(stopwatch_hacker_debuggable) + " secs")

                self.output_and_force_print_console(
                    "Total elapsed time: " + str(stopwatch_total_elapsed_time) + " secs")
            else:
                self.output("AndroBugs analyzing time: " + str(stopwatch_analyze_time) + " secs")
                self.output(
                    "HACKER_DEBUGGABLE_CHECK elapsed time: " + str(stopwatch_hacker_debuggable) + " secs")
                self.output("Total elapsed time: " + str(stopwatch_total_elapsed_time) + " secs")

        if args.store_analysis_result_in_db:

            analysis_tips_output = "("

            if args.analyze_engine_build:
                analysis_tips_output += "analyze_engine_build: " + str(args.analyze_engine_build) + ", "

            if args.analyze_tag:
                analysis_tips_output += "analyze_tag: " + str(args.analyze_tag) + ", "

            if analysis_tips_output.endswith(", "):
                analysis_tips_output = analysis_tips_output[:-2]

            analysis_tips_output += ")"

            if (REPORT_OUTPUT == "file"):
                self.output_and_force_print_console(
                    "<<< Analysis result has stored into database " + analysis_tips_output + " >>>")
            else:
                self.output("<<< Analysis result has stored into database " + analysis_tips_output + " >>>")
