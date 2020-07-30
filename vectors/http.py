from vector_base import VectorBase
from constants import *
from engines import *

class Vector(VectorBase):
    description = "HttpURLConnection bug checking"
    tags = ["HTTPURLCONNECTION_BUG"]

    def analyze(self) -> None:
        # HttpURLConnection bug checking:

        """
            Example Java code:
                private void disableConnectionReuseIfNecessary() {
                    // Work around pre-Froyo bugs in HTTP connection reuse.
                    if (Integer.parseInt(Build.VERSION.SDK) < Build.VERSION_CODES.FROYO) {
                        System.setProperty("http.keepAlive", "false");
                    }
                }

            Example Bytecode code:
                const-string v0, "http.keepAlive"
                const-string v1, "false"
                invoke-static {v0, v1}, Ljava/lang/System;->setProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

        """
        if (self.int_min_sdk is not None) and (self.int_min_sdk <= 8):

            pkg_http_url_connection = self.analysis.find_classes("Ljava/net/HttpURLConnection;")
            pkg_http_url_connection = self.filtering_engine.filter_class_analysis_list(pkg_http_url_connection)

            # Check only when using the HttpURLConnection
            if pkg_http_url_connection:

                list_pre_froyo_http_url_connection = []
                path_pre_froyo_http_url_connection = self.analysis.find_methods(
                    "Ljava/lang/System;", "setProperty", "\(Ljava/lang/String; Ljava/lang/String;\)Ljava/lang/String;")

                has_http_keepAlive_Name = False
                has_http_keep_alive_value = False

                for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(path_pre_froyo_http_url_connection):
                    if i.getResult()[0] == "http.keepAlive":
                        has_http_keepAlive_Name = True
                        list_pre_froyo_http_url_connection.append(i.getPath())  # Only list the "false" one
                        if i.getResult()[1] == "false":
                            has_http_keep_alive_value = True
                            break

                if has_http_keepAlive_Name:
                    if has_http_keep_alive_value:
                        self.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_INFO,
                                           "HttpURLConnection Android Bug Checking",
                                           "System property \"http.keepAlive\" for \"HttpURLConnection\" sets correctly.")

                    else:
                        output_string = """You should set System property "http.keepAlive" to "false"
        You're using "HttpURLConnection". Prior to Android 2.2 (Froyo), "HttpURLConnection" had some frustrating bugs. 
        In particular, calling close() on a readable InputStream could poison the connection pool. Work around this by disabling connection pooling:
        Please check the reference:
         (1)http://developer.android.com/reference/java/net/HttpURLConnection.html
         (2)http://android-developers.blogspot.tw/2011/09/androids-http-clients.html"""
                        self.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_NOTICE,
                                           "HttpURLConnection Android Bug Checking",
                                           output_string)

                        self.writer.show_Paths(list_pre_froyo_http_url_connection)  # Notice: list_pre_Froyo_HttpURLConnection
                else:
                    output_string = """You're using "HttpURLConnection". Prior to Android 2.2 (Froyo), "HttpURLConnection" had some frustrating bugs. 
        In particular, calling close() on a readable InputStream could poison the connection pool. Work around this by disabling connection pooling. 
        Please check the reference: 
         (1)http://developer.android.com/reference/java/net/HttpURLConnection.html
         (2)http://android-developers.blogspot.tw/2011/09/androids-http-clients.html"""

                    self.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_NOTICE, "HttpURLConnection Android Bug Checking",
                                       output_string)
                    # Make it optional to list library
                    self.writer.show_xrefs_class_analysis_list(pkg_http_url_connection)  # Notice: pkg_HttpURLConnection

            else:
                self.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_INFO, "HttpURLConnection Android Bug Checking",
                                   "Ignore checking \"http.keepAlive\" because you're not using \"HttpURLConnection\".")

        else:
            self.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_INFO, "HttpURLConnection Android Bug Checking",
                               "Ignore checking \"http.keepAlive\" because you're not using \"HttpURLConnection\" and min_Sdk > 8.")
