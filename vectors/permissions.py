import re

from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks if app has correct permissions"

    def analyze(self) -> None:

        all_permissions = self.apk.get_permissions()

        # ACCESS_MOCK_LOCATION check
        if "android.permission.ACCESS_MOCK_LOCATION" in all_permissions:
            self.writer.startWriter("USE_PERMISSION_ACCESS_MOCK_LOCATION", LEVEL_CRITICAL,
                                    "Unnecessary Permission Checking",
                                    "Permission 'android.permission.ACCESS_MOCK_LOCATION' only works in emulator environment. Please remove this permission if it is a released application.")
        else:
            self.writer.startWriter("USE_PERMISSION_ACCESS_MOCK_LOCATION", LEVEL_INFO,
                                    "Unnecessary Permission Checking",
                                    "Permission 'android.permission.ACCESS_MOCK_LOCATION' sets correctly.")

        # Empty permissionGroup check
        # TODO test dit
        permissions = self.apk.get_android_manifest_xml().findall("permission")

        permissions_with_empty_permission_group = list()
        permissionGroupRe = re.compile(".*:permissionGroup=\"\".*")
        for permission in permissions:
            for attribute in permissions.attrib:
                if permissionGroupRe.match(attribute) and permissions.attrib[attribute] is not None:
                    permissions_with_empty_permission_group.append(permission)  # TODO get name of permission

        if permissions_with_empty_permission_group:  # If the list is not empty
            self.writer.startWriter("PERMISSION_GROUP_EMPTY_VALUE", LEVEL_CRITICAL,
                                    "AndroidManifest PermissionGroup Checking",
                                    "Setting the 'permissionGroup' attribute an empty value will make the permission definition become invalid and no other apps will be able to use the permission.")

            for permission_name in permissions_with_empty_permission_group:
                self.writer.write(
                    "Permission name '%s' sets an empty value in `permissionGroup` attribute." % (permission_name))
        else:
            self.writer.startWriter("PERMISSION_GROUP_EMPTY_VALUE", LEVEL_INFO,
                                    "AndroidManifest PermissionGroup Checking",
                                    "PermissionGroup in permission tag of AndroidManifest sets correctly.")

        # Critical use-permission check:
        user_permission_critical_manufacturer = ["android.permission.INSTALL_PACKAGES",
                                                 "android.permission.WRITE_SECURE_SETTINGS"]
        user_permission_critical = ["android.permission.MOUNT_FORMAT_FILESYSTEMS",
                                    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
                                    "android.permission.RESTART_PACKAGES"]

        list_user_permission_critical_manufacturer = []
        list_user_permission_critical = []

        for permission in all_permissions:
            if permission in user_permission_critical_manufacturer:
                list_user_permission_critical_manufacturer.append(permission)
            if permission in user_permission_critical:
                list_user_permission_critical.append(permission)

        if list_user_permission_critical_manufacturer or list_user_permission_critical:
            if list_user_permission_critical_manufacturer:
                self.writer.startWriter("USE_PERMISSION_SYSTEM_APP", LEVEL_CRITICAL,
                                        "AndroidManifest System Use Permission Checking",
                                        "This app should only be released and signed by device manufacturer or Google and put under '/system/app'. If not, it may be a malicious app.")

                for permission in list_user_permission_critical_manufacturer:
                    self.writer.write("System use-permission found: \"" + permission + "\"")

            if list_user_permission_critical:
                self.writer.startWriter("USE_PERMISSION_CRITICAL", LEVEL_CRITICAL,
                                        "AndroidManifest Critical Use Permission Checking",
                                        "This app has very high privileges. Use it carefully.")

                for permission in list_user_permission_critical:
                    self.writer.write("Critical use-permission found: \"" + permission + "\"")
        else:
            self.writer.startWriter("USE_PERMISSION_SYSTEM_APP", LEVEL_INFO,
                                    "AndroidManifest System Use Permission Checking",
                                    "No system-level critical use-permission found.")

        # INTERNET check
        pkg_URLConnection = self.analysis.is_class_present("Ljava/net/URLConnection;")
        pkg_HttpURLConnection = self.analysis.is_class_present("Ljava/net/HttpURLConnection;")
        pkg_HttpsURLConnection = self.analysis.is_class_present("Ljavax/net/ssl/HttpsURLConnection;")
        pkg_DefaultHttpClient = self.analysis.is_class_present("Lorg/apache/http/impl/client/DefaultHttpClient;")
        pkg_HttpClient = self.analysis.is_class_present("Lorg/apache/http/client/HttpClient;")

        if pkg_URLConnection or pkg_HttpURLConnection or pkg_HttpsURLConnection or pkg_DefaultHttpClient or pkg_HttpClient:

            if "android.permission.INTERNET" in all_permissions:
                self.writer.startWriter("USE_PERMISSION_INTERNET", LEVEL_INFO, "Accessing the Internet Checking",
                                        "This app is using the Internet via HTTP protocol.")
            else:
                self.writer.startWriter("USE_PERMISSION_INTERNET", LEVEL_CRITICAL, "Accessing the Internet Checking",
                                        "This app has some internet accessing codes but does not have 'android.permission.INTERNET' use-permission in AndroidManifest.")
        else:
            self.writer.startWriter("USE_PERMISSION_INTERNET", LEVEL_INFO, "Accessing the Internet Checking",
                                    "No HTTP-related connection codes found.")


