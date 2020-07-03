from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks if an unprotected keystore is present"

    def analyze(self) -> None:
        list_no_pwd_probably_ssl_pinning_keystore = []
        list_no_pwd_keystore = []
        list_protected_keystore = []

        path_KeyStore = self.analysis.find_methods("Ljava/security/KeyStore;", "load", "(Ljava/io/InputStream; [C)V")
        path_KeyStore = self.filtering_engine.filter_list_of_paths(self.dalvik, path_KeyStore)
        # TODO: Implement method `trace_Register_value_by_Param_in_source_Paths` from modified AndroGuard framework.
        for i in self.analysis.trace_Register_value_by_Param_in_source_Paths(self.dalvik, path_KeyStore):
            if i.getResult()[2] == 0:  # null = 0 = Not using password
                if (i.is_class_container(1)):
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

                for keystore in list_no_pwd_probably_ssl_pinning_keystore:
                    self.writer.show_Path(self.dalvik, keystore)

            if list_no_pwd_keystore:
                self.writer.startWriter("HACKER_KEYSTORE_NO_PWD", LEVEL_CRITICAL, "KeyStore Protection Checking",
                                        "The Keystores below seem \"NOT\" protected by password (Total: " + str(
                                            len(list_no_pwd_keystore)) + "). Please manually check:",
                                        ["KeyStore", "Hacker"])

                for keystore in list_no_pwd_keystore:
                    self.writer.show_Path(self.dalvik, keystore)

            if list_protected_keystore:
                self.writer.startWriter("HACKER_KEYSTORE_SSL_PINNING2", LEVEL_NOTICE, "KeyStore Protection Information",
                                        "The Keystores below are \"protected\" by password and seem using SSL-pinning (Total: " + str(
                                            len(
                                                list_protected_keystore)) + "). You can use \"Portecle\" tool to manage the certificates in the KeyStore:",
                                        ["KeyStore", "Hacker"])
                for keystore in list_protected_keystore:
                    self.writer.show_Path(self.dalvik, keystore)
