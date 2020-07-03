from engines import FilteringEngine
from vector_base import VectorBase
from constants import *

class Vector(VectorBase):
    description = "Checks Master Key Type I Vulnerability "

    def analyze(self) -> None:
        # WebView addJavascriptInterface checking:

        # Don't match class name because it might use the subclass of WebView
        path_WebView_addJavascriptInterface = self.analysis.find_methods(
            methodname="addJavascriptInterface", descriptor="(Ljava/lang/Object; Ljava/lang/String;)V")
        path_WebView_addJavascriptInterface = self.filtering_engine.filter_list_of_paths(self.dalvik,
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
