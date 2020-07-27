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
            "Landroid/webkit/WebView;", "setWebViewClient", "\(Landroid/webkit/WebViewClient;\)V")
        dic_webview_client_new_instance = self.filtering_engine.\
            get_class_container_dict_by_new_instance_classname_in_method_class_analysis_list(path_webview_client_new_instance, 1)

        # Second, find which class and method extends it
        list_webview_client = []
        methods_webviewClient = helper_functions.get_method_ins_by_superclass_and_method(self.dalvik, ["Landroid/webkit/WebViewClient;"],
                                                                        "onReceivedSslError",
                                                                        "(Landroid/webkit/WebView; Landroid/webkit/SslErrorHandler; Landroid/net/http/SslError;)V")
        for method in methods_webviewClient:
            if helper_functions.is_kind_string_in_ins_method(method, "Landroid/webkit/SslErrorHandler;->proceed()V"):
                list_webview_client.append(method)

        # TODO needs fixing
        # list_webview_client = self.filtering_engine.filter_method_class_analysis_list(list_webview_client)

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
                self.writer.write("%s-> %s%s" % (method.get_class_name(), method.get_name(), method.get_descriptor()))

                # because one class may initialize by many new instances of it
                method_class_name = method.get_class_name()    # TODO needs fixing
                if method_class_name in dic_webview_client_new_instance:
                    self.writer.show_Paths(dic_webview_client_new_instance[method_class_name])

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
            "Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "\(Z\)V")
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
            self.writer.show_Paths(list_set_java_script_enabled_xss)
        else:
            self.writer.startWriter("WEBVIEW_JS_ENABLED", LEVEL_INFO, "WebView Potential XSS Attacks Checking",
                               "Did not detect \"setJavaScriptEnabled(true)\" in WebView.", ["WebView"])

        # WebView addJavascriptInterface checking:

        # Don't match class name because it might use the subclass of WebView
        path_WebView_addJavascriptInterface = self.analysis.find_methods(
            methodname="addJavascriptInterface", descriptor="\(Ljava/lang/Object; Ljava/lang/String;\)V")
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
            self.writer.show_xrefs_method_class_analysis_list(path_WebView_addJavascriptInterface)

        else:

            self.writer.startWriter("WEBVIEW_RCE", LEVEL_INFO, "WebView RCE Vulnerability Checking",
                                    "WebView addJavascriptInterface vulnerabilities not found.",
                                    ["WebView", "Remote Code Execution"], "CVE-2013-4710")

        # WebView setAllowFileAccess:

        """
            Get all "dst" class: Landroid/webkit/WebSettings;
              => Categorized by src function,
                 If the src function:
                   1.setAllowFileAccess does not exist    OR
                   2.setAllowFileAccess(true)
                       =>src function may be vulnerable

            **Why check WebSettings? It's because WebView almost always uses the method: WebView->getSettings()

            **Even if the below example, it will finally call WebSettings:
              class TestWebView extends WebView {
                public TestWebView(Context context) {
                  super(context);
                }
              }
        """

        webview_websettings_class_analysis_list = self.analysis.find_classes("Landroid/webkit/WebSettings;")
        webview_websettings_class_analysis_list = self.filtering_engine.filter_class_analysis_list(webview_websettings_class_analysis_list)

        webview_websettings_method_class_analysis_list = []
        for class_analysis in webview_websettings_class_analysis_list:
            for method_class_analysis in class_analysis.get_methods():
                if method_class_analysis.name == "setAllowFileAccess":
                    webview_websettings_method_class_analysis_list.append(method_class_analysis)

        paths_webview_websettings_set_allow_file_access_true = []
        for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(webview_websettings_method_class_analysis_list):
            if i.getResult()[1] == 0x1:  # setAllowFileAccess is true
                paths_webview_websettings_set_allow_file_access_true.append(i.getPath())

        # setAllowFileAccess is true by default for apps targeting Build.VERSION_CODES.Q and below, and false when
        # targeting Build.VERSION_CODES.R and above.
        if paths_webview_websettings_set_allow_file_access_true \
                or (not webview_websettings_method_class_analysis_list and webview_websettings_class_analysis_list):
            self.writer.startWriter("WEBVIEW_ALLOW_FILE_ACCESS", LEVEL_WARNING,
                                    "WebView Local File Access Attacks Checking",
                                    (    "Found \"setAllowFileAccess(true)\" or not set(enabled by default) in WebView. The attackers could inject malicious script into WebView and exploit the opportunity to access local resources. This can be mitigated or prevented by disabling local file system access. (It is enabled by default)\n"
                                        "         Note that this enables or disables file system access only. Assets and resources are still accessible using file:///android_asset and file:///android_res.\n"
                                        "         The attackers can use \"mWebView.loadUrl(\"file:///data/data/[Your_Package_Name]/[File]\");\" to access app's local file.\n"
                                        "         Reference: (1)https://labs.mwrinfosecurity.com/blog/2012/04/23/adventures-with-android-webviews/\n"
                                        "                    (2)http://developer.android.com/reference/android/webkit/WebSettings.html#setAllowFileAccess(boolean)\n"
                                        "         Please add or modify \"yourWebView.getSettings().setAllowFileAccess(false)\" to your WebView:\n"
                                        "         "), ["WebView"])
            if paths_webview_websettings_set_allow_file_access_true:
                self.writer.write("Methods where setAllowFileAccess(true)")
                self.writer.show_Paths(paths_webview_websettings_set_allow_file_access_true)
            elif webview_websettings_class_analysis_list:
                self.writer.write("Classes where WebSettings is used, and setAllowFileAccess might be enabled by default")
                self.writer.show_xrefs_class_analysis_list(webview_websettings_class_analysis_list)

        else:
            self.writer.startWriter("WEBVIEW_ALLOW_FILE_ACCESS", LEVEL_INFO,
                                    "WebView Local File Access Attacks Checking",
                                    "Did not find potentially critical local file access settings.", ["WebView"])
