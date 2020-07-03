from vector_base import VectorBase
from constants import *
from engines import *
import utils
import base64

STR_REGEXP_TYPE_EXCLUDE_CLASSES = "^(Landroid/support/|Lcom/actionbarsherlock/|Lorg/apache/)"
ENABLE_EXCLUDE_CLASSES = True


class Vector(VectorBase):
    description = "Checks if there are any Base64 encoded strings present and decodes them"

    def analyze(self) -> None:
        # TODO use androguard analysis.find_strings method
        efficient_string_search_engine = EfficientStringSearchEngine()
        filtering_engine = FilteringEngine(ENABLE_EXCLUDE_CLASSES, STR_REGEXP_TYPE_EXCLUDE_CLASSES)

        all_strings = self.dalvik.get_strings()
        all_urls_strip_duplicated = []

        # ------------------------------------------------------------------------
        # [Important: String Efficient Searching Engine]
        # >>>>STRING_SEARCH<<<<
        # addSearchItem params: (1)match_id  (2)regex or string(url or string you want to find), (3)is using regex for parameter 2
        efficient_string_search_engine.addSearchItem("$__possibly_check_root__", re.compile("/system/bin"),
                                                     True)  # "root" checking
        efficient_string_search_engine.addSearchItem("$__possibly_check_su__", "su", False)  # "root" checking2
        efficient_string_search_engine.addSearchItem("$__sqlite_encryption__", re.compile("PRAGMA\s*key\s*=", re.I),
                                                     True)  # SQLite encryption checking

        # print("------------------------------------------------------------")

        # Print all urls without SSL:

        exception_url_string = ["http://example.com",
                                "http://example.com/",
                                "http://www.example.com",
                                "http://www.example.com/",
                                "http://www.google-analytics.com/collect",
                                "http://www.google-analytics.com",
                                "http://hostname/?",
                                "http://hostname/"]

        for line in all_strings:
            if re.match('http\:\/\/(.+)', line):  # ^https?\:\/\/(.+)$
                all_urls_strip_duplicated.append(line)

        all_urls_strip_non_duplicated = sorted(set(all_urls_strip_duplicated))
        all_urls_strip_non_duplicated_final = []

        if all_urls_strip_non_duplicated:
            for url in all_urls_strip_non_duplicated:
                if (url not in exception_url_string) and (not url.startswith("http://schemas.android.com/")) and \
                        (not url.startswith("http://www.w3.org/")) and \
                        (not url.startswith("http://apache.org/")) and \
                        (not url.startswith("http://xml.org/")) and \
                        (not url.startswith("http://localhost/")) and \
                        (not url.startswith("http://java.sun.com/")) and \
                        (not url.endswith("/namespace")) and \
                        (not url.endswith("-dtd")) and \
                        (not url.endswith(".dtd")) and \
                        (not url.endswith("-handler")) and \
                        (not url.endswith("-instance")):
                    # >>>>STRING_SEARCH<<<<
                    efficient_string_search_engine.addSearchItem(url, url, False)  # use url as "key"
                    all_urls_strip_non_duplicated_final.append(url)

        efficient_string_search_engine.addSearchItem("android.intent.action.MY_PACKAGE_REPLACED", "android.intent.action.MY_PACKAGE_REPLACED", False)  # use url as "key"
        # ------------------------------------------------------------------------

        # Base64 String decoding:
        list_base64_success_decoded_string_to_original_mapping = {}
        list_base64_excluded_original_string = ["endsWith", "allCells", "fillList", "endNanos", "cityList", "cloudid=",
                                                "Liouciou"]  # exclusion lis

        for line in all_strings:
            if (utils.is_base64(line)) and (len(line) >= 3):
                try:
                    decoded_string = base64.b64decode(line)
                    if utils.is_success_base64_decoded_string(decoded_string):
                        if len(decoded_string) > 3:
                            if (decoded_string not in list_base64_success_decoded_string_to_original_mapping) and (
                                    line not in list_base64_excluded_original_string):
                                list_base64_success_decoded_string_to_original_mapping[decoded_string] = line
                                # >>>>STRING_SEARCH<<<<
                                efficient_string_search_engine.addSearchItem(line, line, False)
                except:
                    pass

        # ------------------------------------------------------------------------

        # start the search core engine
        efficient_string_search_engine.search(self.dalvik, all_strings)

        # ------------------------------------------------------------------------

        # pre-run to avoid all the urls are in exclusion list but the results are shown
        all_urls_strip_non_duplicated_final_prerun_count = 0
        for url in all_urls_strip_non_duplicated_final:
            dict_class_to_method_mapping = efficient_string_search_engine.get_search_result_dict_key_classname_value_methodlist_by_match_id(
                url)
            if filtering_engine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping):
                all_urls_strip_non_duplicated_final_prerun_count = all_urls_strip_non_duplicated_final_prerun_count + 1

        if all_urls_strip_non_duplicated_final_prerun_count != 0:
            self.writer.startWriter("SSL_URLS_NOT_IN_HTTPS", LEVEL_CRITICAL, "SSL Connection Checking",
                                    "URLs that are NOT under SSL (Total:" + str(
                                        all_urls_strip_non_duplicated_final_prerun_count) + "):", ["SSL_Security"])

            for url in all_urls_strip_non_duplicated_final:

                dict_class_to_method_mapping = efficient_string_search_engine.get_search_result_dict_key_classname_value_methodlist_by_match_id(
                    url)
                if not filtering_engine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping):
                    continue

                self.writer.write(url)

                try:
                    if dict_class_to_method_mapping:  # Found the corresponding url in the code
                        for _, result_method_list in list(dict_class_to_method_mapping.items()):
                            for result_method in result_method_list:  # strip duplicated item
                                if filtering_engine.is_class_name_not_in_exclusion(result_method.get_class_name()):
                                    source_classes_and_functions = (
                                            result_method.get_class_name() + "->" + result_method.get_name() + result_method.get_descriptor())
                                    self.writer.write("    => " + source_classes_and_functions)

                except KeyError:
                    pass

        else:
            self.writer.startWriter("SSL_URLS_NOT_IN_HTTPS", LEVEL_INFO, "SSL Connection Checking",
                                    "Did not discover urls that are not under SSL (Notice: if you encrypt the url string, we can not discover that).",
                                    ["SSL_Security"])

        # Base64 String decoding:
        organized_list_base64_success_decoded_string_to_original_mapping = []
        for decoded_string, original_string in list(list_base64_success_decoded_string_to_original_mapping.items()):
            dict_class_to_method_mapping = efficient_string_search_engine.get_search_result_dict_key_classname_value_methodlist_by_match_id(
                original_string)
            if filtering_engine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping):
                """
                    All of same string found are inside the excluded packages.
                    Only the strings found the original class will be added.
                """
                organized_list_base64_success_decoded_string_to_original_mapping.append(
                    (decoded_string, original_string, dict_class_to_method_mapping))

        if organized_list_base64_success_decoded_string_to_original_mapping:  # The result is from the upper code section

            list_base64_decoded_urls = {}

            self.writer.startWriter("HACKER_BASE64_STRING_DECODE", LEVEL_CRITICAL, "Base64 String Encryption",
                                    "Found Base64 encoding \"String(s)\" (Total: " + str(len(
                                        organized_list_base64_success_decoded_string_to_original_mapping)) + "). We cannot guarantee all of the Strings are Base64 encoding and also we will not show you the decoded binary file:",
                                    ["Hacker"])

            for decoded_string, original_string, dict_class_to_method_mapping in organized_list_base64_success_decoded_string_to_original_mapping:

                self.writer.write(decoded_string)
                self.writer.write("    ->Original Encoding String: " + original_string)

                if dict_class_to_method_mapping:
                    for class_name, result_method_list in list(dict_class_to_method_mapping.items()):
                        for result_method in result_method_list:
                            source_classes_and_functions = (
                                    result_method.get_class_name() + "->" + result_method.get_name() + result_method.get_descriptor())
                            self.writer.write("    ->From class: " + source_classes_and_functions)

                if "http://" in decoded_string:
                    list_base64_decoded_urls[decoded_string] = original_string

            if list_base64_decoded_urls:

                self.writer.startWriter("HACKER_BASE64_URL_DECODE", LEVEL_CRITICAL, "Base64 String Encryption",
                                        "Base64 encoding \"HTTP URLs without SSL\" from all the Strings (Total: " + str(
                                            len(list_base64_decoded_urls)) + ")", ["SSL_Security", "Hacker"])

                for decoded_string, original_string in list(list_base64_decoded_urls.items()):

                    dict_class_to_method_mapping = efficient_string_search_engine.get_search_result_dict_key_classname_value_methodlist_by_match_id(
                        original_string)

                    if not filtering_engine.is_all_of_key_class_in_dict_not_in_exclusion(
                            dict_class_to_method_mapping):  # All of the same string found are inside the excluded packages
                        continue

                    self.writer.write(decoded_string)
                    self.writer.write("    ->Original Encoding String: " + original_string)

                    if dict_class_to_method_mapping:
                        for class_name, result_method_list in list(dict_class_to_method_mapping.items()):
                            for result_method in result_method_list:
                                source_classes_and_functions = (
                                        result_method.get_class_name() + "->" + result_method.get_name() + result_method.get_descriptor())
                                self.writer.write("    ->From class: " + source_classes_and_functions)

        else:
            self.writer.startWriter("HACKER_BASE64_STRING_DECODE", LEVEL_INFO, "Base64 String Encryption",
                                    "No encoded Base64 String or Urls found.", ["Hacker"])
