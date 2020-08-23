import staticDVM
from vector_base import VectorBase
import helper_functions
import re
from constants import *


class Vector(VectorBase):
    description = "Checks SSL Implementation, and verifies if application has any SSL practices allowing MITM attacks"
    tags = ["SSL_CN2", "SSL_CN3",
            "SSL_DEFAULT_SCHEME_NAME", "SSL_X509"]

    def analyze(self) -> None:

        regex_excluded_class_names = re.compile(STR_REGEXP_TYPE_EXCLUDE_CLASSES)

        # HTTPS ALLOW_ALL_HOSTNAME_VERIFIER checking:

        """
            Example Java code:
                HttpsURLConnection.setDefaultHostnameVerifier(org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

            Example Bytecode code (The same bytecode for those two Java code):
                (1)
                sget-object v11, Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER:Lorg/apache/http/conn/ssl/X509HostnameVerifier;
                invoke-static {v11}, Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V

                (2)
                   new-instance v11, Lcom/example/androidsslconnecttofbtest/MainActivity$2;
                invoke-direct {v11, p0}, Lcom/example/androidsslconnecttofbtest/MainActivity$2;-><init>(Lcom/example/androidsslconnecttofbtest/MainActivity;)V
                invoke-static {v11}, Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V

            Scenario:
                https://www.google.com/  => Google (SSL certificate is valid, CN: www.google.com)
                https://60.199.175.18   => IP of Google (SSL certificate is invalid, See Chrome error message.
        """

        # (1)inner class checking

        # First, find out who calls it
        path_HOSTNAME_INNER_VERIFIER = list(self.analysis.find_methods(
            "Ljavax/net/ssl/HttpsURLConnection;", "setDefaultHostnameVerifier", "\(Ljavax/net/ssl/HostnameVerifier;\)V"))
        # classname "Lorg/apache/http/conn/ssl/SSLSocketFactory;"
        path_HOSTNAME_INNER_VERIFIER2 = list(self.analysis.find_methods(
            methodname="setHostnameVerifier",
            descriptor="\(Lorg/apache/http/conn/ssl/X509HostnameVerifier;\)V"))
        path_HOSTNAME_INNER_VERIFIER.extend(path_HOSTNAME_INNER_VERIFIER2)

        dic_path_HOSTNAME_INNER_VERIFIER_new_instance = self.filtering_engine.get_class_container_dict_by_new_instance_classname_in_method_class_analysis_list(path_HOSTNAME_INNER_VERIFIER, 1)  # parameter index 1

        # TODO might need filtering?

        # Second, find the called custom classes
        list_HOSTNAME_INNER_VERIFIER = []

        methods_hostnameverifier = []
        for dalvik in self.dalvik:
            methods_hostnameverifier.extend(helper_functions. \
                                            get_method_ins_by_implement_interface_and_method(dalvik,
                                                                                             ["Ljavax/net/ssl/HostnameVerifier;"],
                                                                                             TYPE_COMPARE_ANY,
                                                                                             "verify",
                                                                                             "(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z"))
        for method in methods_hostnameverifier:
            register_analyzer = staticDVM.RegisterAnalyzerVMImmediateValue(method.get_instructions())
            if register_analyzer.get_ins_return_boolean_value():  # Has security problem
                list_HOSTNAME_INNER_VERIFIER.append(method)

        list_HOSTNAME_INNER_VERIFIER = self.filtering_engine.filter_method_list(list_HOSTNAME_INNER_VERIFIER)

        if list_HOSTNAME_INNER_VERIFIER:

            output_string = """This app allows Self-defined HOSTNAME VERIFIER to accept all Common Names(CN). 
        This is a critical vulnerability and allows attackers to do MITM attacks with his valid certificate without your knowledge. 
        Case example: 
        (1)http://osvdb.org/96411 
        (2)http://www.wooyun.org/bugs/wooyun-2010-042710 
        (3)http://www.wooyun.org/bugs/wooyun-2010-052339
        Also check Google doc: http://developer.android.com/training/articles/security-ssl.html (Caution: Replacing HostnameVerifier can be very dangerous). 
        OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
        Check this book to see how to solve this issue: http://goo.gl/BFb65r 

        To see what's the importance of Common Name(CN) verification.
        Use Google Chrome to navigate:
         - https://www.google.com   => SSL certificate is valid
         - https://60.199.175.158/  => This is the IP address of google.com, but the CN is not match, making the certificate invalid. You still can go Google.com but now you cannot distinguish attackers from normal users

        Please check the code inside these methods:"""

            self.writer.startWriter("SSL_CN1", LEVEL_CRITICAL,
                                    "SSL Implementation Checking (Verifying Host Name in Custom Classes)",
                                    output_string,
                                    ["SSL_Security"])

            for method in list_HOSTNAME_INNER_VERIFIER:
                self.writer.write(method.get_class_name() + "->" + method.get_name() + method.get_descriptor())

                # because one class may initialize by many new instances of it
                method_class_name = method.get_class_name()
                if method_class_name in dic_path_HOSTNAME_INNER_VERIFIER_new_instance:
                    self.writer.show_Paths(
                                           dic_path_HOSTNAME_INNER_VERIFIER_new_instance[method_class_name])
        else:
            self.writer.startWriter("SSL_CN1", LEVEL_INFO,
                                    "SSL Implementation Checking (Verifying Host Name in Custom Classes)",
                                    "Self-defined HOSTNAME VERIFIER checking OK.", ["SSL_Security"])

        # (2)ALLOW_ALL_HOSTNAME_VERIFIER fields checking

        path_HOSTNAME_INNER_VERIFIER_new_instance = None
        if "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;" in dic_path_HOSTNAME_INNER_VERIFIER_new_instance:
            path_HOSTNAME_INNER_VERIFIER_new_instance = dic_path_HOSTNAME_INNER_VERIFIER_new_instance[
                "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;"]

        path_HOSTNAME_INNER_VERIFIER_in_params = None
        if 'Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER Lorg/apache/http/conn/ssl/X509HostnameVerifier;' in dic_path_HOSTNAME_INNER_VERIFIER_new_instance:
            path_HOSTNAME_INNER_VERIFIER_in_params = dic_path_HOSTNAME_INNER_VERIFIER_new_instance['Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER Lorg/apache/http/conn/ssl/X509HostnameVerifier;']
        # fields_ALLOW_ALL_HOSTNAME_VERIFIER = list(self.analysis.find_fields(fieldname="ALLOW_ALL_HOSTNAME_VERIFIER",
        #                                                                     fieldtype="Lorg/apache/http/conn/ssl/X509HostnameVerifier;"))
        #
        # filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths = []
        # for field in fields_ALLOW_ALL_HOSTNAME_VERIFIER:
        #     for xref_class, xref_method in field.get_xref_read():
        #         if not regex_excluded_class_names.match(xref_class.name):
        #             filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths.append(xref_method)

        if path_HOSTNAME_INNER_VERIFIER_new_instance or path_HOSTNAME_INNER_VERIFIER_in_params:

            output_string = """This app does not check the validation of the CN(Common Name) of the SSL certificate ("ALLOW_ALL_HOSTNAME_VERIFIER" field or "AllowAllHostnameVerifier" class). 
        This is a critical vulnerability and allows attackers to do MITM attacks with his valid certificate without your knowledge. 
        Case example:
        (1)http://osvdb.org/96411 
        (2)http://www.wooyun.org/bugs/wooyun-2010-042710 
        (3)http://www.wooyun.org/bugs/wooyun-2010-052339
        Also check Google doc: http://developer.android.com/training/articles/security-ssl.html (Caution: Replacing HostnameVerifier can be very dangerous).
        OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
        Check this book to see how to solve this issue: http://goo.gl/BFb65r 

        To see what's the importance of Common Name(CN) verification.
        Use Google Chrome to navigate:
         - https://www.google.com   => SSL certificate is valid
         - https://60.199.175.158/  => This is the IP address of google.com, but the CN is not match, making the certificate invalid. You still can go Google.com but now you cannot distinguish attackers from normal users

        Please check the code inside these methods:"""

            self.writer.startWriter("SSL_CN2", LEVEL_CRITICAL,
                                    "SSL Implementation Checking (Verifying Host Name in Fields)",
                                    output_string, ["SSL_Security"])

            # if filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths:
            #     """
            #         Example code:
            #         SSLSocketFactory factory = SSLSocketFactory.getSocketFactory();
            #         factory.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
            #     """
            #     for method in filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths:
            #         self.writer.write("=> %s ---> %s" % (method.get_class_name(), method.name))

            if path_HOSTNAME_INNER_VERIFIER_new_instance:
                """
                    Example code: 
                    SSLSocketFactory factory = SSLSocketFactory.getSocketFactory();
                    factory.setHostnameVerifier(new AllowAllHostnameVerifier());
                """
                # For this one, the exclusion procedure is done on earlier
                self.writer.show_Paths(path_HOSTNAME_INNER_VERIFIER_new_instance)

            if path_HOSTNAME_INNER_VERIFIER_in_params:
                """
                    Example code: 
                    SSLSocketFactory factory = SSLSocketFactory.getSocketFactory();
                    x = factory.ALLOW_ALL_HOSTNAME_VERIFIER;
                    factory.setHostnameVerifier(x);
                """
                # For this one, the exclusion procedure is done on earlier
                self.writer.show_Paths(path_HOSTNAME_INNER_VERIFIER_in_params)
        else:
            self.writer.startWriter("SSL_CN2", LEVEL_INFO,
                                    "SSL Implementation Checking (Verifying Host Name in Fields)",
                                    "Critical vulnerability \"ALLOW_ALL_HOSTNAME_VERIFIER\" field setting or \"AllowAllHostnameVerifier\" class instance not found.",
                                    ["SSL_Security"])

        # SSL getInsecure

        list_getInsecure = []
        path_get_insecure = self.analysis.find_methods(
            "Landroid/net/SSLCertificateSocketFactory;", "getInsecure",
            "\(I Landroid/net/SSLSessionCache;\)Ljavax/net/ssl/SSLSocketFactory;")
        path_get_insecure = staticDVM.get_paths(path_get_insecure)

        if path_get_insecure:

            output_string = """Sockets created using this factory(insecure method "getInsecure") are vulnerable to man-in-the-middle attacks. 
        Check the reference: http://developer.android.com/reference/android/net/SSLCertificateSocketFactory.html#getInsecure(int, android.net.SSLSessionCache). 
        Please remove the insecure code:"""

            self.writer.startWriter("SSL_CN3", LEVEL_CRITICAL, "SSL Implementation Checking (Insecure component)",
                                    output_string,
                                    ["SSL_Security"])
            self.writer.show_Paths(path_get_insecure)
        else:
            self.writer.startWriter("SSL_CN3", LEVEL_INFO, "SSL Implementation Checking (Insecure component)",
                                    "Did not detect SSLSocketFactory by insecure method \"getInsecure\".",
                                    ["SSL_Security"])

        # HttpHost default scheme "http"

        """
            Check this paper to see why I designed this vector: "The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software"


            Java Example code:
                HttpHost target = new HttpHost(uri.getHost(), uri.getPort(), HttpHost.DEFAULT_SCHEME_NAME);

            Smali Example code:
                const-string v4, "http"
                invoke-direct {v0, v2, v3, v4}, Lorg/apache/http/HttpHost;-><init>(Ljava/lang/String; I Ljava/lang/String;)V
        """

        list_http_host_scheme_http = []
        path_http_host_scheme_http = self.analysis.find_methods(
            "Lorg/apache/http/HttpHost;", "<init>", "\(Ljava/lang/String; I Ljava/lang/String;\)V")
        for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(
                                                                         path_http_host_scheme_http):
            if i.getResult()[3] is None:
                continue
            if i.is_string(i.getResult()[3]) and i.getResult()[3].lower() == "http":
                list_http_host_scheme_http.append(i.getPath())

        if list_http_host_scheme_http:
            self.writer.startWriter("SSL_DEFAULT_SCHEME_NAME", LEVEL_CRITICAL, "SSL Implementation Checking (HttpHost)",
                                    "This app uses \"HttpHost\", but the default scheme is \"http\" or \"HttpHost.DEFAULT_SCHEME_NAME(http)\". Please change to \"https\":",
                                    ["SSL_Security"])

            self.writer.show_Paths(list_http_host_scheme_http)
        else:
            self.writer.startWriter("SSL_DEFAULT_SCHEME_NAME", LEVEL_INFO, "SSL Implementation Checking (HttpHost)",
                                    "DEFAULT_SCHEME_NAME for HttpHost check: OK", ["SSL_Security"])

        # SSL Verification Fail (To check whether the code verifies the certificate)
        methods_X509TrustManager_list = helper_functions. \
                get_method_ins_by_implement_interface_and_method_desc_dict(self.dalvik,
                                                                           ["Ljavax/net/ssl/X509TrustManager;"],
                                                                           TYPE_COMPARE_ANY,
                                                                           [
                                                                               "getAcceptedIssuers()[Ljava/security/cert/X509Certificate;",
                                                                               "checkClientTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V",
                                                                               "checkServerTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V"
                                                                           ]
                                                                           )


        list_X509Certificate_Critical_class = []
        list_X509Certificate_Warning_class = []

        for class_name, method_list in list(methods_X509TrustManager_list.items()):
            ins_count = 0

            for method in method_list:
                for ins in method.get_instructions():
                    ins_count = ins_count + 1

            if ins_count <= 4:
                # Critical
                list_X509Certificate_Critical_class.append(class_name)
            else:
                # Warning
                list_X509Certificate_Warning_class.append(class_name)

        if list_X509Certificate_Critical_class or list_X509Certificate_Warning_class:

            log_level = LEVEL_WARNING
            log_partial_prefix_msg = "Please make sure this app has the conditions to check the validation of SSL Certificate. If it's not properly checked, it MAY allows self-signed, expired or mismatch CN certificates for SSL connection."

            if list_X509Certificate_Critical_class:
                log_level = LEVEL_CRITICAL
                log_partial_prefix_msg = "This app DOES NOT check the validation of SSL Certificate. It allows self-signed, expired or mismatch CN certificates for SSL connection."

            list_X509Certificate_merge_list = []
            list_X509Certificate_merge_list.extend(list_X509Certificate_Critical_class)
            list_X509Certificate_merge_list.extend(list_X509Certificate_Warning_class)

            dict_X509Certificate_class_name_to_caller_mapping = {}

            for dalvik in self.dalvik:
                for method in dalvik.get_methods():
                    for i in method.get_instructions():  # method.get_instructions(): Instruction
                        if i.get_op_value() == 0x22:  # 0x22 = "new-instance"
                            if i.get_string() in list_X509Certificate_merge_list:
                                referenced_class_name = i.get_string()
                                if referenced_class_name not in dict_X509Certificate_class_name_to_caller_mapping:
                                    dict_X509Certificate_class_name_to_caller_mapping[referenced_class_name] = []

                                dict_X509Certificate_class_name_to_caller_mapping[referenced_class_name].append(method)

            self.writer.startWriter("SSL_X509", log_level, "SSL Certificate Verification Checking",
                               log_partial_prefix_msg + """
    This is a critical vulnerability and allows attackers to do MITM attacks without your knowledge.
    If you are transmitting users' username or password, these sensitive information may be leaking.
    Reference:
    (1)OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
    (2)Android Security book: http://goo.gl/BFb65r 
    (3)https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=134807561
    This vulnerability is much more severe than Apple's "goto fail" vulnerability: http://goo.gl/eFlovw
    Please do not try to create a "X509Certificate" and override "checkClientTrusted", "checkServerTrusted", and "getAcceptedIssuers" functions with blank implementation.
    We strongly suggest you use the existing API instead of creating your own X509Certificate class. 
    Please modify or remove these vulnerable code: 
    """, ["SSL_Security"])
            if list_X509Certificate_Critical_class:
                self.writer.write("[Confirm Vulnerable]")
                for name in list_X509Certificate_Critical_class:
                    self.writer.write("=> " + name)
                    if name in dict_X509Certificate_class_name_to_caller_mapping:
                        for used_method in dict_X509Certificate_class_name_to_caller_mapping[name]:
                            self.writer.write(
                                "      -> used by: " + used_method.get_class_name() + "->" + used_method.get_name() + used_method.get_descriptor())

            if list_X509Certificate_Warning_class:
                self.writer.write("--------------------------------------------------")
                self.writer.write("[Maybe Vulnerable (Please manually confirm)]")
                for name in list_X509Certificate_Warning_class:
                    self.writer.write("=> " + name)
                    if name in dict_X509Certificate_class_name_to_caller_mapping:
                        for used_method in dict_X509Certificate_class_name_to_caller_mapping[name]:
                            self.writer.write(
                                "      -> used by: " + used_method.get_class_name() + "->" + used_method.get_name() + used_method.get_descriptor())

        else:
            self.writer.startWriter("SSL_X509", LEVEL_INFO, "SSL Certificate Verification Checking",
                                    "Did not find vulnerable X509Certificate code.", ["SSL_Security"])
