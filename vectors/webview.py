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
        for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(path_set_java_script_enabled_xss):
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

        # WebView addJavascriptInterface checking:

        # Don't match class name because it might use the subclass of WebView
        path_WebView_addJavascriptInterface = self.analysis.find_methods(
            methodname="addJavascriptInterface", descriptor="(Ljava/lang/Object; Ljava/lang/String;)V")
        path_WebView_addJavascriptInterface = self.filtering_engine.filter_method_class_analysis_list(
                                                                                    path_WebView_addJavascriptInterface)

        if path_WebView_addJavascriptInterface:

            output_string = """Found a critical WebView "addJavascriptInterface" vulnerability. This method can be used to allow JavaScript to control the host application. 
                This is a powerful feature, but also presents a security risk for applications targeted to API level JELLY_BEAN(4.2) or below, because JavaScript could use reflection to access an injected object's public fields. Use of this method in a WebView containing untrusted content could allow an attacker to manipulate the host application in unintended ways, executing Java code with the permissions of the host application. 
                Reference: 
                  1."http://developer.android.com/reference/android/webkit/WebView.html#addJavascriptInterface(java.lang.Object, java.lang.String) "
                  2.https://labs.mwrinfosecurity.com/blog/2013/09/24/webview-addjavascriptinterface-remote-code-execution/
                  3.http://50.56.33.56/blog/?p=314
                  4.http://blog.trustlook.com/2013/09/04/alert-android-webview-addjavascriptinterface-code-execution-vulnerability/
                Please modify the below code:"""

            self.writer.startWriter("WEBVIEW_RCE", LEVEL_CRITICAL, "WebView RCE Vulnerability Checking", output_string,
                                    ["WebView", "Remote Code Execution"], "CVE-2013-4710")
            self.writer.show_Paths(self.dalvik, path_WebView_addJavascriptInterface)

        else:

            self.writer.startWriter("WEBVIEW_RCE", LEVEL_INFO, "WebView RCE Vulnerability Checking",
                                    "WebView addJavascriptInterface vulnerabilities not found.",
                                    ["WebView", "Remote Code Execution"], "CVE-2013-4710")

        # WebView setAllowFileAccess:
    #
    #     """
    #         Get all "dst" class: Landroid/webkit/WebSettings;
    #           => Categorized by src function,
    #              If the src function:
    #                1.setAllowFileAccess does not exist    OR
    #                2.setAllowFileAccess(true)
    #                    =>src function may be vulnerable
    #
    #         **Why check WebSettings? It's because WebView almost always uses the method: WebView->getSettings()
    #
    #         **Even if the below example, it will finally call WebSettings:
    #           class TestWebView extends WebView {
    #             public TestWebView(Context context) {
    #               super(context);
    #             }
    #           }
    #     """
    #
    #     pkg_WebView_WebSettings = self.analysis.is_class_present("Landroid/webkit/WebSettings;")
    #     pkg_WebView_WebSettings = self.filtering_engine.filter_list_of_paths(self.dalvik, pkg_WebView_WebSettings)
    #
    #     dict_WebSettings_ClassMethod_to_Path = {}
    #
    #     for path in pkg_WebView_WebSettings:
    #         src_class_name, src_method_name, src_descriptor = path.get_src(cm)
    #         dst_class_name, dst_method_name, dst_descriptor = path.get_dst(cm)
    #
    #         dict_name = src_class_name + "->" + src_method_name + src_descriptor
    #         if dict_name not in dict_WebSettings_ClassMethod_to_Path:
    #             dict_WebSettings_ClassMethod_to_Path[dict_name] = []
    #
    #         dict_WebSettings_ClassMethod_to_Path[dict_name].append((dst_method_name + dst_descriptor, path))
    #
    #     path_setAllowFileAccess_vulnerable_ready_to_test = []
    #     path_setAllowFileAccess_confirm_vulnerable_src_class_func = []
    #
    #     for class_fun_descriptor, value in list(dict_WebSettings_ClassMethod_to_Path.items()):
    #         has_Settings = False
    #         for func_name_descriptor, path in value:
    #             if func_name_descriptor == "setAllowFileAccess(Z)V":
    #                 has_Settings = True
    #
    #                 # Add ready-to-test Path list
    #                 path_setAllowFileAccess_vulnerable_ready_to_test.append(path)
    #                 break
    #
    #         if not has_Settings:
    #             # Add vulnerable Path list
    #             path_setAllowFileAccess_confirm_vulnerable_src_class_func.append(class_fun_descriptor)
    #
    #     for i in staticDVM.trace_register_value_by_param_in_source_paths(path_setAllowFileAccess_vulnerable_ready_to_test):
    #         if (i.getResult()[1] == 0x1):  # setAllowFileAccess is true
    #
    #             path = i.getPath()
    #             src_class_name, src_method_name, src_descriptor = path.get_src(cm)
    #             dict_name = src_class_name + "->" + src_method_name + src_descriptor
    #
    #             if dict_name not in path_setAllowFileAccess_confirm_vulnerable_src_class_func:
    #                 path_setAllowFileAccess_confirm_vulnerable_src_class_func.append(dict_name)
    #
    #     if path_setAllowFileAccess_confirm_vulnerable_src_class_func:
    #
    #         path_setAllowFileAccess_confirm_vulnerable_src_class_func = sorted(
    #             set(path_setAllowFileAccess_confirm_vulnerable_src_class_func))
    #
    #         self.writer.startWriter("WEBVIEW_ALLOW_FILE_ACCESS", LEVEL_WARNING,
    #                            "WebView Local File Access Attacks Checking",
    #                            """Found "setAllowFileAccess(true)" or not set(enabled by default) in WebView. The attackers could inject malicious script into WebView and exploit the opportunity to access local resources. This can be mitigated or prevented by disabling local file system access. (It is enabled by default)
    # Note that this enables or disables file system access only. Assets and resources are still accessible using file:///android_asset and file:///android_res.
    # The attackers can use "mWebView.loadUrl("file:///data/data/[Your_Package_Name]/[File]");" to access app's local file.
    # Reference: (1)https://labs.mwrinfosecurity.com/blog/2012/04/23/adventures-with-android-webviews/
    #            (2)http://developer.android.com/reference/android/webkit/WebSettings.html#setAllowFileAccess(boolean)
    # Please add or modify "yourWebView.getSettings().setAllowFileAccess(false)" to your WebView:
    # """, ["WebView"])
    #         for i in path_setAllowFileAccess_confirm_vulnerable_src_class_func:
    #             self.writer.write(i)
    #
    #     else:
    #         self.writer.startWriter("WEBVIEW_ALLOW_FILE_ACCESS", LEVEL_INFO,
    #                            "WebView Local File Access Attacks Checking",
    #                            "Did not find potentially critical local file access settings.", ["WebView"])
