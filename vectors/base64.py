import constants
from vector_base import VectorBase
from constants import *
from engines import *
import utils
import base64

list_base64_excluded_original_string = ["endsWith", "allCells", "fillList", "endNanos", "cityList", "cloudid=",
                                        "Liouciou"]  # exclusion list

class Vector(VectorBase):
    description = "Checks if there are any Base64 encoded strings present and decodes them"
    tags = ["HACKER_BASE64_STRING_DECODE", "SSL_Security"]

    def analyze(self) -> None:
        strings_analysis = self.analysis.get_strings_analysis()

        # Check all strings that seem to be base64 encoded

        regex_excluded_class_names = re.compile(constants.STR_REGEXP_TYPE_EXCLUDE_CLASSES)
        found_strings = []

        for string, string_analysis in strings_analysis.items():
            if utils.is_base64(string) and len(string) >= 3 and string not in list_base64_excluded_original_string:
                try:
                    decoded_string = base64.b64decode(string).decode()
                    if utils.is_success_base64_decoded_string(decoded_string) and len(decoded_string) > 3:
                        if not all([regex_excluded_class_names.match(xref_class.name)
                                    for xref_class, xref_method in string_analysis.get_xref_from()]):
                            found_strings.append((string, decoded_string, string_analysis))
                except:
                    pass

        if found_strings:
            self.writer.startWriter("HACKER_BASE64_STRING_DECODE", LEVEL_CRITICAL,
                                    "Base64 String Encryption",
                                    "Found Base64 encoding \"String(s)\" (Total: %d ). We cannot guarantee all of the "
                                    "Strings are Base64 encoding and also we will not show you the decoded binary "
                                    "file:" % len(found_strings),
                                    ["Hacker"])

            base64_decoded_urls = []
            for original_string, decoded_string, string_analysis in found_strings:
                self.writer.write(decoded_string)
                self.writer.write("    ->Original Encoding String: " + original_string)
                self._print_xrefs(string_analysis)

                if decoded_string.startswith("http://"):
                    base64_decoded_urls.append((decoded_string, original_string))

            if base64_decoded_urls:
                self.writer.startWriter("HACKER_BASE64_URL_DECODE", LEVEL_CRITICAL, "Base64 String Encryption",
                                        "Base64 encoding \"HTTP URLs without SSL\""
                                        "from all the Strings (Total: %d)" % len(base64_decoded_urls),
                                        ["SSL_Security", "Hacker"])

                for original_string, decoded_string, string_analysis in found_strings:
                    self.writer.write(decoded_string)
                    self.writer.write("    ->Original Encoding String: " + original_string)
                    self._print_xrefs(string_analysis)

        else:
            self.writer.startWriter("HACKER_BASE64_STRING_DECODE", LEVEL_INFO, "Base64 String Encryption",
                                    "No encoded Base64 String or Urls found.", ["Hacker"])

        # Check all URL like strings without SSL

        unfiltered_urls = []
        for string in strings_analysis:
            if re.match('http://(.+)', string):
                unfiltered_urls.append(string)

        exception_url_string = ["http://example.com",
                                "http://example.com/",
                                "http://www.example.com",
                                "http://www.example.com/",
                                "http://www.google-analytics.com/collect",
                                "http://www.google-analytics.com",
                                "http://hostname/?",
                                "http://hostname/"]

        unfiltered_urls = sorted(set(unfiltered_urls))
        filtered_urls = []

        if unfiltered_urls:
            for url in unfiltered_urls:
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
                    string_analysis = strings_analysis[url]
                    # only append url if it is not in the exclusion list
                    if not all([regex_excluded_class_names.match(xref_class.name)
                                for xref_class, xref_method in string_analysis.get_xref_from()]):
                        filtered_urls.append(url)

        if filtered_urls:
            self.writer.startWriter("SSL_URLS_NOT_IN_HTTPS", LEVEL_CRITICAL, "SSL Connection Checking",
                                    "URLs that are NOT under SSL (Total: %d):" % len(filtered_urls),
                                    ["SSL_Security"])

            for url in filtered_urls:
                self.writer.write(url)
                self._print_xrefs(strings_analysis[url])
        else:
            self.writer.startWriter("SSL_URLS_NOT_IN_HTTPS", LEVEL_INFO, "SSL Connection Checking",
                                    "Did not discover urls that are not under SSL (Notice: if you encrypt the url "
                                    "string, we can not discover that).",
                                    ["SSL_Security"])

