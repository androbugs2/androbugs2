import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = " Checks if an unprotected keystore is present, and if the application uses ssl pinning"
    tags = ["HACKER_KEYSTORE_NO_PWD", "HACKER_KEYSTORE_SSL_PINNING",
            "HACKER_KEYSTORE_LOCATION1", "HACKER_KEYSTORE_LOCATION2",
            "KEYSTORE_TYPE_CHECK"]

    def analyze(self) -> None:
        list_no_pwd_probably_ssl_pinning_keystore = []
        list_no_pwd_keystore = []
        list_protected_keystore = []

        path_key_store = self.analysis.find_methods("Ljava/security/KeyStore;", "load", "\(Ljava/io/InputStream; \[C\)V")
        for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(path_key_store):
            if i.getResult()[2] == 0:  # null = 0 = Not using password
                if i.is_class_container(1):
                    clz_invoked = i.getResult()[1]
                    if clz_invoked.get_class_name() == "Ljava/io/ByteArrayInputStream;":
                        list_no_pwd_probably_ssl_pinning_keystore.append(i.getPath())
                    else:
                        list_no_pwd_keystore.append(i.getPath())
                else:
                    if i.getResult()[1] == 0:  # null = 0
                        list_no_pwd_probably_ssl_pinning_keystore.append(i.getPath())
                    else:
                        list_no_pwd_keystore.append(i.getPath())
            else:
                list_protected_keystore.append(i.getPath())

        if (not list_no_pwd_keystore) and (not list_protected_keystore) and (
                not list_no_pwd_probably_ssl_pinning_keystore):

            self.writer.startWriter("HACKER_KEYSTORE_NO_PWD", LEVEL_INFO, "KeyStore Protection Checking",
                                    "Ignore checking KeyStore protected by password or not because you're not using KeyStore.",
                                    ["KeyStore", "Hacker"])

        else:
            if list_no_pwd_probably_ssl_pinning_keystore:

                self.writer.startWriter("HACKER_KEYSTORE_SSL_PINNING", LEVEL_CRITICAL, "KeyStore Protection Checking",
                                        "The Keystores below seem using \"byte array\" or \"hard-coded cert info\" to do SSL pinning (Total: " + str(
                                            len(
                                                list_no_pwd_probably_ssl_pinning_keystore)) + "). Please manually check:",
                                        ["KeyStore", "Hacker"])

                self.writer.show_Paths(list_no_pwd_probably_ssl_pinning_keystore)

            if list_no_pwd_keystore:
                self.writer.startWriter("HACKER_KEYSTORE_NO_PWD", LEVEL_CRITICAL, "KeyStore Protection Checking",
                                        "The Keystores below seem \"NOT\" protected by password (Total: " + str(
                                            len(list_no_pwd_keystore)) + "). Please manually check:",
                                        ["KeyStore", "Hacker"])

                self.writer.show_Paths(list_no_pwd_keystore)

            if list_protected_keystore:
                self.writer.startWriter("HACKER_KEYSTORE_SSL_PINNING2", LEVEL_NOTICE, "KeyStore Protection Information",
                                        "The Keystores below are \"protected\" by password and seem using SSL-pinning (Total: " + str(
                                            len(
                                                list_protected_keystore)) + "). You can use \"Portecle\" tool to manage the certificates in the KeyStore:",
                                        ["KeyStore", "Hacker"])
                self.writer.show_Paths(list_protected_keystore)

        # Find all keystore

        list_keystore_file_name = []
        list_possible_keystore_file_name = []

        for name, _, _ in self.apk.get_files_information():
            """
                1.Name includes cert (search under /res/raw)
                2.ends with .bks (search all)
            """
            if name.endswith(".bks") or name.endswith(".jks"):
                if (name.startswith("res/")) and (
                        not name.startswith("res/raw/")):  # If any files found on "/res" dir, only get from "/res/raw"
                    continue
                list_keystore_file_name.append(name)
            elif ("keystore" in name) or ("cert" in name):
                if (name.startswith("res/")) and (
                        not name.startswith("res/raw/")):  # If any files found on "/res" dir, only get from "/res/raw
                    continue
                list_possible_keystore_file_name.append(name)

        if list_keystore_file_name or list_possible_keystore_file_name:
            if list_keystore_file_name:
                self.writer.startWriter("HACKER_KEYSTORE_LOCATION1", LEVEL_NOTICE, "KeyStore File Location",
                                        "BKS Keystore file:", ["KeyStore", "Hacker"])
                for i in list_keystore_file_name:
                    self.writer.write(i)

            if list_possible_keystore_file_name:
                self.writer.startWriter("HACKER_KEYSTORE_LOCATION2", LEVEL_NOTICE, "Possible KeyStore File Location",
                                        "BKS possible keystore file:", ["KeyStore", "Hacker"])
                for i in list_possible_keystore_file_name:
                    self.writer.write(i)
        else:
            self.writer.startWriter("HACKER_KEYSTORE_LOCATION1", LEVEL_INFO, "KeyStore File Location",
                                    "Did not find any possible BKS keystores or certificate keystore file (Notice: It does not mean this app does not use keystore):",
                                    ["KeyStore", "Hacker"])

        # BKS KeyStore checking:

        """
            Example:
            const-string v11, "BKS"
            invoke-static {v11}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;
        """

        list_non_bks_keystore = []
        path_bks_key_store = self.analysis.find_methods("Ljava/security/KeyStore;", "getInstance",
                                                        "\(Ljava/lang/String;\)Ljava/security/KeyStore;")

        for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(
                                                                         path_bks_key_store):
            if i.getResult()[0] is None:
                continue
            if (i.is_string(i.getResult()[0])) and ((i.getResult()[0]).upper() != "BKS"):
                list_non_bks_keystore.append(i.getPath())

        if list_non_bks_keystore:
            self.writer.startWriter("KEYSTORE_TYPE_CHECK", LEVEL_CRITICAL, "KeyStore Type Checking",
                                    "Android only accept 'BKS' type KeyStore. Please confirm you are using 'BKS' type KeyStore:",
                                    ["KeyStore"])
            self.writer.show_Paths(list_non_bks_keystore)
        else:
            self.writer.startWriter("KEYSTORE_TYPE_CHECK", LEVEL_INFO, "KeyStore Type Checking",
                                    "KeyStore 'BKS' type check OK",
                                    ["KeyStore"])