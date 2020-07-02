import re


class EfficientStringSearchEngine:
    """
		Usage:
			1.create an EfficientStringSearchEngine instance (only one should be enough)
			2.addSearchItem
			3.search
			4.get_search_result_by_match_id or get_search_result_dict_key_classname_value_methodlist_by_match_id
	"""

    def __init__(self):
        self.__prog_list = []
        self.__dict_result_identifier_to_search_result_list = {}

    def addSearchItem(self, match_id, search_regex_or_fix_string_condition, isRegex):
        self.__prog_list.append((match_id, search_regex_or_fix_string_condition, isRegex))  # "root" checking

    def search(self, vm, allstrings_list):

        """
			Example prog list input:
				[ ("match1", re.compile("PRAGMA\s*key\s*=", re.I), True), ("match2", re.compile("/system/bin/"), True), ("match3", "/system/bin/", False) ]

			Example return (Will always return the corresponding key, but the value is return only when getting the result):
				{ "match1": [ (Complete_String_found, EncoddedMethod), (Complete_String_found, EncoddedMethod) ] , "match2": [] }
		"""

        ## [String Search Performance Profiling]
        # string_finding_start = datetime.now()

        self.__dict_result_identifier_to_search_result_list.clear()

        for identifier, _, _ in self.__prog_list:  # initializing the return result list
            if identifier not in self.__dict_result_identifier_to_search_result_list:
                self.__dict_result_identifier_to_search_result_list[identifier] = []

        dict_string_value_to_idx_from_file_mapping = {}

        for idx_from_file, string_value in vm.get_all_offset_from_file_and_string_value_mapping():  # get a dictionary of string value and string idx mapping
            dict_string_value_to_idx_from_file_mapping[string_value] = idx_from_file

        ## [String Search Performance Profiling]
        # string_loading_end = datetime.now()
        # print("Time for loading String: " + str(((string_loading_end - string_finding_start).total_seconds())))

        list_strings_idx_to_find = []  # string idx list
        dict_string_idx_to_identifier = {}  # Example: (52368, "match1")

        # Get the searched strings into search idxs
        for line in allstrings_list:
            for identifier, regexp, isRegex in self.__prog_list:
                if (isRegex and regexp.search(line)) or ((not isRegex) and (regexp == line)):
                    if line in dict_string_value_to_idx_from_file_mapping:  # Find idx by string
                        string_idx = dict_string_value_to_idx_from_file_mapping[line]
                        list_strings_idx_to_find.append(string_idx)
                        dict_string_idx_to_identifier[string_idx] = identifier

        list_strings_idx_to_find = set(list_strings_idx_to_find)  # strip duplicated items

        ## [String Search Performance Profiling]
        # string_finding_end = datetime.now()
        # print("Time for finding String: " + str((string_finding_end - string_finding_start).total_seconds()))

        if list_strings_idx_to_find:
            cm = vm.get_class_manager()
            for method in vm.get_methods():
                for i in method.get_instructions():  # method.get_instructions(): Instruction
                    if (i.get_op_value() == 0x1A) or (
                            i.get_op_value() == 0x1B):  # 0x1A = "const-string", 0x1B = "const-string/jumbo"
                        ref_kind_idx = cm.get_offset_idx_by_from_file_top_idx(i.get_ref_kind())
                        if ref_kind_idx in list_strings_idx_to_find:  # find string_idx in string_idx_list
                            if ref_kind_idx in dict_string_idx_to_identifier:
                                original_identifier_name = dict_string_idx_to_identifier[ref_kind_idx]
                                self.__dict_result_identifier_to_search_result_list[original_identifier_name].append(
                                    (i.get_string(), method))

        ## [String Search Performance Profiling]
        # elapsed_string_finding_time = datetime.now() - string_finding_start
        # print("String Search Elapsed time: " + str(elapsed_string_finding_time.total_seconds()))
        # print("------------------------------------------------------------")

        return self.__dict_result_identifier_to_search_result_list

    def get_search_result_by_match_id(self, match_id):
        return self.__dict_result_identifier_to_search_result_list[match_id]

    def get_search_result_dict_key_classname_value_methodlist_by_match_id(self, match_id):
        """
			Input: [ (Complete_String_found, EncoddedMethod), (Complete_String_found, EncoddedMethod) ] or []
			Output: dicionary key by class name
		"""
        dict_result = {}

        search_result_value = self.__dict_result_identifier_to_search_result_list[match_id]

        try:
            if search_result_value:  # Found the corresponding url in the code
                result_list = set(search_result_value)

                for _, result_method in result_list:  # strip duplicated item
                    class_name = result_method.get_class_name()
                    if class_name not in dict_result:
                        dict_result[class_name] = []

                    dict_result[class_name].append(result_method)
        except KeyError:
            pass

        return dict_result


class FilteringEngine:

    def __init__(self, enable_exclude_classes, str_regexp_type_excluded_classes):
        self.__enable_exclude_classes = enable_exclude_classes
        self.__str_regexp_type_excluded_classes = str_regexp_type_excluded_classes
        self.__regexp_excluded_classes = re.compile(self.__str_regexp_type_excluded_classes, re.I)

    def get_filtering_regexp(self):
        return self.__regexp_excluded_classes

    def filter_efficient_search_result_value(self, result):

        if result is None:
            return []
        if (not self.__enable_exclude_classes):
            return result

        l = []
        for found_string, method in result:
            if not self.__regexp_excluded_classes.match(method.get_class_name()):
                l.append((found_string, method))

        return l

    def is_class_name_not_in_exclusion(self, class_name):
        if self.__enable_exclude_classes:
            if self.__regexp_excluded_classes.match(class_name):
                return False
            else:
                return True
        else:
            return True

    def is_all_of_key_class_in_dict_not_in_exclusion(self, dict_result):
        if self.__enable_exclude_classes:
            isAllMatchExclusion = True
            for class_name, method_list in list(dict_result.items()):
                if not self.__regexp_excluded_classes.match(class_name):  # any match
                    isAllMatchExclusion = False

            if isAllMatchExclusion:
                return False

            return True
        else:
            return True

    def filter_list_of_methods(self, method_list):
        if self.__enable_exclude_classes and method_list:
            l = []
            for method in method_list:
                if not self.__regexp_excluded_classes.match(method.get_class_name()):
                    l.append(method)
            return l
        else:
            return method_list

    def filter_list_of_classes(self, class_list):
        if self.__enable_exclude_classes and class_list:
            l = []
            for i in class_list:
                if not self.__regexp_excluded_classes.match(i):
                    l.append(i)
            return l
        else:
            return class_list

    def filter_list_of_paths(self, vm, paths):
        if self.__enable_exclude_classes and paths:
            cm = vm.get_class_manager()

            l = []
            for path in paths:
                src_class_name, src_method_name, src_descriptor = path.get_src(cm)
                if not self.__regexp_excluded_classes.match(src_class_name):
                    l.append(path)

            return l
        else:
            return paths

    def filter_dst_class_in_paths(self, vm, paths, excluded_class_list):
        cm = vm.get_class_manager()

        l = []
        for path in paths:
            dst_class_name, _, _ = path.get_dst(cm)
            if dst_class_name not in excluded_class_list:
                l.append(path)

        return l

    def filter_list_of_variables(self, vm, paths):
        """
			Example paths input: [[('R', 8), 5050], [('R', 24), 5046]]
		"""

        if self.__enable_exclude_classes and paths:
            l = []
            for path in paths:
                access, idx = path[0]
                m_idx = path[1]
                method = vm.get_cm_method(m_idx)
                class_name = method[0]

                if not self.__regexp_excluded_classes.match(class_name):
                    l.append(path)
            return l
        else:
            return paths

    def get_class_container_dict_by_new_instance_classname_in_paths(self, vm, analysis, paths,
                                                                    result_idx):  # dic: key=>class_name, value=>paths
        dic_classname_to_paths = {}
        paths = self.filter_list_of_paths(vm, paths)
        for i in analysis.trace_Register_value_by_Param_in_source_Paths(vm, paths):
            if (i.getResult()[result_idx] is None) or (
                    not i.is_class_container(
                        result_idx)):  # If parameter 0 is a class_container type (ex: Lclass/name;)
                continue
            class_container = i.getResult()[result_idx]
            class_name = class_container.get_class_name()
            if class_name not in dic_classname_to_paths:
                dic_classname_to_paths[class_name] = []
            dic_classname_to_paths[class_name].append(i.getPath())
        return dic_classname_to_paths
