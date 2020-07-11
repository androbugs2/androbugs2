import helper_functions
import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks if an unprotected keystore is present"

    def analyze(self) -> None:
        # WebViewClient onReceivedSslError errors

        # First, find out who calls setWebViewClient
        path_webview_client_new_instance = self.analysis.find_methods(
            "Landroid/webkit/WebView;", "setWebViewClient", "(Landroid/webkit/WebViewClient;)V")
        dic_webview_client_new_instance = self.filtering_engine.get_class_container_dict_by_new_instance_classname_in_paths(self.dalvik,
                                                                                                                           self.analysis,
                                                                                                                           path_webview_client_new_instance,
                                                                                                                           1)

        # Second, find which class and method extends it
        list_webview_client = []
        methods_webviewClient = helper_functions.get_method_ins_by_superclass_and_method(self.dalvik, ["Landroid/webkit/WebViewClient;"],
                                                                        "onReceivedSslError",
                                                                        "(Landroid/webkit/WebView; Landroid/webkit/SslErrorHandler; Landroid/net/http/SslError;)V")
        for method in methods_webviewClient:
            if helper_functions.is_kind_string_in_ins_method(method, "Landroid/webkit/SslErrorHandler;->proceed()V"):
                list_webview_client.append(method)

        list_webview_client = self.filtering_engine.filter_method_class_analysis_list(list_webview_client)

        if list_webview_client:
            self.writer.startWriter("SSL_WEBVIEW", LEVEL_CRITICAL, "SSL Implementation Checking (WebViewClient for WebView)",
                               """DO NOT use "handler.proceed();" inside those methods in extended "WebViewClient", which allows the connection even if the SSL Certificate is invalid (MITM Vulnerability).
    References:
    (1)A View To A Kill: WebView Exploitation: https://www.iseclab.org/papers/webview_leet13.pdf 
    (2)OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
    (3)https://jira.appcelerator.org/browse/TIMOB-4488
    Vulnerable codes:
    """, ["SSL_Security"])

            for method in list_webview_client:
                self.writer.write(method.easy_print())

                # because one class may initialize by many new instances of it
                method_class_name = method.get_class_name()
                if method_class_name in dic_webview_client_new_instance:
                    self.writer.show_Paths(self.dalvik, dic_webview_client_new_instance[method_class_name])

        else:
            self.writer.startWriter("SSL_WEBVIEW", LEVEL_INFO, "SSL Implementation Checking (WebViewClient for WebView)",
                               "Did not detect critical usage of \"WebViewClient\"(MITM Vulnerability).",
                               ["SSL_Security"])

        # WebView setJavaScriptEnabled - Potential XSS:

        """
            Java Example code:
                webView1 = (WebView)findViewById(R.id.webView1);
                webView1.setWebViewClient(new ExtendedWebView());
                WebSettings webSettings = webView1.getSettings();
                webSettings.setJavaScriptEnabled(true);

            Smali Example code:
                const/4 v1, 0x1
                invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
        """

        list_set_java_script_enabled_xss = []
        path_set_java_script_enabled_xss = self.analysis.find_methods(
            "Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "(Z)V")
        path_set_java_script_enabled_xss = self.filtering_engine.filter_method_class_analysis_list(path_set_java_script_enabled_xss)
        for i in staticDVM.trace_register_value_by_param_in_source_paths( path_set_java_script_enabled_xss):
            if i.getResult()[1] is None:
                continue
            if i.getResult()[1] == 0x1:
                list_set_java_script_enabled_xss.append(i.getPath())

        if list_set_java_script_enabled_xss:
            self.writer.startWriter("WEBVIEW_JS_ENABLED", LEVEL_WARNING, "WebView Potential XSS Attacks Checking",
                               "Found \"setJavaScriptEnabled(true)\" in WebView, which could exposed to potential XSS attacks. Please check the web page code carefully and sanitize the output:",
                               ["WebView"])
            for i in list_set_java_script_enabled_xss:
                self.writer.show_Path(self.dalvik, i)
        else:
            self.writer.startWriter("WEBVIEW_JS_ENABLED", LEVEL_INFO, "WebView Potential XSS Attacks Checking",
                               "Did not detect \"setJavaScriptEnabled(true)\" in WebView.", ["WebView"])