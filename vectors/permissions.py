import collections
import re
import utils
from vector_base import VectorBase
from constants import *


PROTECTION_NORMAL = 0   # "normal" or not set
PROTECTION_DANGEROUS = 1
PROTECTION_SIGNATURE = 2
PROTECTION_SIGNATURE_OR_SYSTEM = 3
PROTECTION_MASK_BASE = 15
PROTECTION_FLAG_SYSTEM = 16
PROTECTION_FLAG_DEVELOPMENT = 32
PROTECTION_MASK_FLAGS = 240

class Vector(VectorBase):
    description = "Checks if app has correct permissions"
    tags = ["USE_PERMISSION_ACCESS_MOCK_LOCATION", "PERMISSION_GROUP_EMPTY_VALUE",
            "USE_PERMISSION_SYSTEM_APP", "USE_PERMISSION_CRITICAL",
            "USE_PERMISSION_SYSTEM_APP", "PERMISSION_NORMAL", "PERMISSION_DANGEROUS",
            "PERMISSION_NO_PREFIX_EXPORTED", "PERMISSION_EXPORTED",
            "PERMISSION_PROVIDER_IMPLICIT_EXPORTED", "PERMISSION_INTENT_FILTER_MISCONFIG",
            "PERMISSION_IMPLICIT_SERVICE"]
    def _get_all_components_by_permission(self, xml, permission):
        """
            Return:
                (1) activity
                (2) activity-alias
                (3) service
                (4) receiver
                (5) provider
            who use the specific permission
        """

        find_tags = ["activity", "activity-alias", "service", "receiver", "provider"]
        dict_perms = {}

        for tag in find_tags:
            for item in utils.get_elements_by_tagname(xml, tag):
                if item.attrib.get("{http://schemas.android.com/apk/res/android}:permission") == permission \
                        or item.attrib.get("{http://schemas.android.com/apk/res/android}:readPermission") == permission \
                        or item.attrib.get(
                    "{http://schemas.android.com/apk/res/android}:writePermission") == permission:
                    if tag not in dict_perms:
                        dict_perms[tag] = []
                    dict_perms[tag].append(item.attrib.get("{http://schemas.android.com/apk/res/android}:name"))
        return dict_perms

    def _print_permission_usage(self, xml, class_name):
        who_use_this_permission = self._get_all_components_by_permission(xml, class_name)
        who_use_this_permission = collections.OrderedDict(sorted(who_use_this_permission.items()))
        if who_use_this_permission:
            for key, value_list in who_use_this_permission.items():
                for item in value_list:
                    self.writer.write("    -> used by (" + key + ") " + item)

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
        xml = self.apk.get_android_manifest_xml()
        permissions = utils.get_elements_by_tagname(xml, "permission")

        permissions_with_empty_permission_group = list()
        permissionGroupRe = re.compile(".*:permissionGroup=\"\".*")
        for permission in permissions:
            for attribute in permission.attrib:
                if permissionGroupRe.match(attribute) and permission.attrib[attribute] is not None:
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

        # Find all "dangerous" and normal custom permissions

        """
            android:permission
            android:readPermission (for ContentProvider)
            android:writePermission (for ContentProvider)
        """

        permissions = self.apk.get_declared_permissions_details()

        dangerous_custom_permissions = []
        normal_or_default_custom_permissions = []

        for name, details in permissions.items():
            try:
                protectionLevel = int(details['protectionLevel'], 16)
            except ValueError:
                protectionLevel = 0

            if protectionLevel == PROTECTION_DANGEROUS:
                dangerous_custom_permissions.append(name)

            elif protectionLevel == PROTECTION_NORMAL:
                normal_or_default_custom_permissions.append(name)

        if dangerous_custom_permissions:
            self.writer.startWriter("PERMISSION_DANGEROUS", LEVEL_CRITICAL,
                                    "AndroidManifest Dangerous ProtectionLevel of Permission Checking",
                                    "The protection level of the below classes is \"dangerous\", allowing any other "
                                    "apps to access this permission (AndroidManifest.xml). The app should declare the "
                                    "permission with the \"android:protectionLevel\" of \"signature\" or "
                                    "\"signatureOrSystem\" so that other apps cannot register and receive message for "
                                    "this app. android:protectionLevel=\"signature\" ensures that apps with request a "
                                    "permission must be signed with same certificate as the application that declared "
                                    "the permission. Please check some related cases: "
                                    "http://www.wooyun.org/bugs/wooyun-2010-039697 Please change these permissions:")

            for class_name in dangerous_custom_permissions:
                self.writer.write(class_name)
                self._print_permission_usage(xml, class_name)

        else:
            self.writer.startWriter("PERMISSION_DANGEROUS", LEVEL_INFO,
                                    "AndroidManifest Dangerous ProtectionLevel of Permission Checking",
                                    "No \"dangerous\" protection level customized permission found (AndroidManifest.xml).")

        if normal_or_default_custom_permissions:
            self.writer.startWriter("PERMISSION_NORMAL", LEVEL_WARNING,
                                    "AndroidManifest Normal ProtectionLevel of Permission Checking",
                                    "The protection level of the below classes is \"normal\" or default ("
                                    "AndroidManifest.xml). The app should declare the permission with the "
                                    "\"android:protectionLevel\" of \"signature\" or \"signatureOrSystem\" so that other "
                                    "apps cannot register and receive message for this app."
                                    "android:protectionLevel=\"signature\" ensures that apps with request a permission "
                                    "must be signed with same certificate as the application that declared the "
                                    "permission. Please make sure these permission are all really need to be exported "
                                    "or otherwise change to \"signature\" or \"signatureOrSystem\" protection level.")
            for class_name in normal_or_default_custom_permissions:
                self.writer.write(class_name)
                self._print_permission_usage(xml, class_name)

        else:
            self.writer.startWriter("PERMISSION_NORMAL", LEVEL_INFO,
                                    "AndroidManifest Normal ProtectionLevel of Permission Checking",
                                    "No default or \"normal\" protection level customized permission found ("
                                    "AndroidManifest.xml).")

        # CHECK Lost "android:" prefix in exported components

        list_lost_exported_components = []
        find_tags = ["activity", "activity-alias", "service", "receiver", "provider"]
        for tag in find_tags:
            for item in utils.get_elements_by_tagname(xml, tag):
                name = item.attrib.get("{http://schemas.android.com/apk/res/android}name")
                exported = item.attrib.get("exported")
                if not utils.is_null_or_empty_string(name) and not utils.is_null_or_empty_string(exported):
                    list_lost_exported_components.append((tag, name))

        if list_lost_exported_components:
            self.writer.startWriter("PERMISSION_NO_PREFIX_EXPORTED", LEVEL_CRITICAL,
                                    "AndroidManifest Exported Lost Prefix Checking",
                                    """Found exported components that forgot to add "android:" prefix (AndroidManifest.xml). 
    Related Cases: (1)http://blog.curesec.com/article/blog/35.html
                   (2)http://safe.baidu.com/2014-07/cve-2013-6272.html
                   (3)http://blogs.360.cn/360mobile/2014/07/08/cve-2013-6272/""", None, "CVE-2013-6272")

            for tag, name in list_lost_exported_components:
                self.writer.write("%10s => %s" % (tag, name))

        else:
            self.writer.startWriter("PERMISSION_NO_PREFIX_EXPORTED", LEVEL_INFO,
                                    "AndroidManifest Exported Lost Prefix Checking",
                                    "No exported components that forgot to add \"android:\" prefix.", None,
                                    "CVE-2013-6272")

        # CHECK "exported" (activity, activity-alias, service, receiver):

        """
    		Remember: Even if the component is protected by "signature" level protection,
    		it still cannot receive the broadcasts from other apps if the component is set to [exported="false"].
    	    ---------------------------------------------------------------------------------------------------

    		Even if the component is exported, it still can be protected by the "android:permission", for example:

    	    <permission
    	        android:name="com.example.androidpermissionexported.PermissionControl"
    	        android:protectionLevel="signature" >
    	    </permission>
    	    <receiver
    	        android:name=".SimpleBroadcastReceiver"
    	        android:exported="true"
    	        android:permission="com.example.androidpermissionexported.PermissionControl" >
    	        <intent-filter>
    	            <action android:name="com.example.androidpermissionexported.PermissionTest" />
    	            <category android:name="android.intent.category.DEFAULT" />
    	        </intent-filter>
    	    </receiver>

    		Apps with the same signature(signed with the same certificate) can send and receive the broadcasts with each other.
    		Conversely, apps that do not have the same signature cannot send and receive the broadcasts with each other.
    		If the protectionLevel is "normal" or not set, then the sending and receiving of broadcasts are not restricted.

    		Even if the Action is used by the app itself, it can still be initialized from external(3rd-party) apps 
    		if the [exported="false"] is not specified, for example:
    	    Intent intent = new Intent("net.emome.hamiapps.am.action.UPDATE_AM");
    	    intent.setClassName("net.emome.hamiapps.am", "net.emome.hamiapps.am.update.UpdateAMActivity");
    	    startActivity(intent);

    	    ---------------------------------------------------------------------------------------

    	    **[PERMISSION_CHECK_STAGE]:
    	        (1)If android:permission not set => Warn it can be accessed from external
    	        (2)If android:permission is set => 
    	            Check its corresponding android:protectionLevel is "not set(default: normal)" or "normal" or "dangerous"=> Warn it can be accessed from external
    	            If the corresponding permission tag is not found => Ignore

    	            **If the names of all the Action(s) are prefixing with "com.android." or "android." =>  Notify with a low priority warning
    	                <receiver android:name="jp.naver.common.android.billing.google.checkout.BillingReceiver">
    	                    <intent-filter>
    	                        <action android:name="com.android.vending.billing.IN_APP_NOTIFY" />
    	                        <action android:name="com.android.vending.billing.RESPONSE_CODE" />
    	                        <action android:name="com.android.vending.billing.PURCHASE_STATE_CHANGED" />
    	                    </intent-filter>
    	                </receiver>
    	            **You need to consider the Multiple Intent, for example:
    	                <receiver android:name=".service.push.SystemBroadcastReceiver">
    	                    <intent-filter android:enabled="true" android:exported="false">
    	                        <action android:name="android.intent.action.BOOT_COMPLETED" />
    	                        <action android:name="android.net.conn.CONNECTIVITY_CHANGE" />
    	                    </intent-filter>
    	                    <intent-filter android:enabled="true" android:exported="false">
    	                        <action android:name="android.intent.action.PACKAGE_REPLACED" />
    	                        <data android:scheme="package" android:path="jp.naver.line.android" />
    	                    </intent-filter>
    	                </receiver>
    	            **The preceding example: intent-filter is set incorrectly. intent-filter does not have the "android:exported" => Warn misconfiguration


    	    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    	    [REASON_REGION_1]
    	    **If exported is not set, the protectionalLevel of android:permission is set to "normal" by default =>
    	        1.It "cannot" be accessed by other apps on Android 4.2 devices 
    	        2.It "can" be accessed by other apps on Android 4.1 devices 

    	    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    	    If it is receiver, service, activity or activity-alias, check if the exported is set:
    	        exported="false" => No problem

    	        exported="true" => Go to [PERMISSION_CHECK_STAGE]

    	        exported is not set => 
    	            If it has any intent-filter:
    	                Yes => Go to [PERMISSION_CHECK_STAGE]
    	                No  => If the intent-filter is not existed, it is exported="false" by default => X(Ignore)

    	        **Main Problem: If it is still necessary to check the setting of "android:permission"


    	    If it is provider, the intent-filter must not exist, so check if the exported is set:
    	        ->[exported="true"] or [exported is not set] :

    	            =>1.If [exported is not set] + [android:targetSdkVersion >= 17], add to the Warning List. Check the reason: [REASON_REGION_1]
    	                It is suggested to add "exported" and tell the users that the default value is not the same among different platforms
    	                => Check Google's document (The default value is "true" for applications that set either android:minSdkVersion or android:targetSdkVersion to "16" or lower. 
    						For applications that set either of these attributes to "17" or higher, the default is "false". - http://developer.android.com/guide/topics/manifest/provider-element.html#exported)

    	            =>2.[PERMISSION_CHECK_STAGE, and check "android:readPermission" and "android:writePermission", and check android:permission, android:writePermission, android:readPermission]
    						=> If any of the corresponding setting for protectionLevel is not found ,then ignore it.
    						   If any of the corresponding setting for protectionLevel is found, warn the users when the protectionLevel is "dangerous" or "normal".

    	        ->exported="false": 
    	            => X(Ignore)
    	"""

        list_ready_to_check = []
        find_tags = ["activity", "activity-alias", "service", "receiver"]
        for tag in find_tags:
            for item in utils.get_elements_by_tagname(xml, tag):
                name = item.attrib.get("{http://schemas.android.com/apk/res/android}name")
                exported = item.attrib.get("{http://schemas.android.com/apk/res/android}exported")
                if not exported:
                    exported = ""
                permission = item.attrib.get("{http://schemas.android.com/apk/res/android}permission")
                if not permission:
                    permission = ""
                has_any_actions_in_intent_filter = False
                if not utils.is_null_or_empty_string(name) and exported.lower() != "false":

                    is_ready_to_check = False
                    is_launcher = False
                    has_any_non_google_actions = False
                    isSyncAdapterService = False
                    for sitem in utils.get_elements_by_tagname(item, "intent-filter"):
                        for ssitem in utils.get_elements_by_tagname(sitem, "action"):
                            has_any_actions_in_intent_filter = True

                            action_name = ssitem.attrib.get("{http://schemas.android.com/apk/res/android}name")
                            if not action_name.startswith("android.") \
                                    and not action_name.startswith("com.android."):
                                has_any_non_google_actions = True

                            if action_name == "android.content.SyncAdapter":
                                isSyncAdapterService = True

                        for ssitem in utils.get_elements_by_tagname(sitem, "category"):
                            category_name = ssitem.attrib.get("{http://schemas.android.com/apk/res/android}name")
                            if category_name == "android.intent.category.LAUNCHER":
                                is_launcher = True

                    # exported="true" or exported not set
                    if exported == "":
                        if has_any_actions_in_intent_filter:
                            # CHECK
                            is_ready_to_check = True

                    elif exported.lower() == "true":  # exported = "true"
                        # CHECK
                        is_ready_to_check = True

                    if is_ready_to_check and not is_launcher:
                        list_ready_to_check.append((tag, name, exported, permission,
                                                    has_any_non_google_actions, has_any_actions_in_intent_filter,
                                                    isSyncAdapterService))
        # ------------------------------------------------------------------------
        # CHECK procedure
        list_implicit_service_components = []

        list_alerting_exposing_components_NonGoogle = []
        list_alerting_exposing_components_Google = []
        for i in list_ready_to_check:
            component = i[0]
            permission = i[3]
            hasAnyNonGoogleActions = i[4]
            has_any_actions_in_intent_filter = i[5]
            isSyncAdapterService = i[6]
            if permission == "" \
                    or permission in dangerous_custom_permissions or permission in normal_or_default_custom_permissions:

                if component == "service" and has_any_actions_in_intent_filter and not isSyncAdapterService:
                    list_implicit_service_components.append(i[1])

                if hasAnyNonGoogleActions:
                    if i not in list_alerting_exposing_components_NonGoogle:
                        list_alerting_exposing_components_NonGoogle.append(i)
                else:
                    if i not in list_alerting_exposing_components_Google:
                        list_alerting_exposing_components_Google.append(i)

        if list_alerting_exposing_components_NonGoogle or list_alerting_exposing_components_Google:
            if list_alerting_exposing_components_NonGoogle:
                self.writer.startWriter("PERMISSION_EXPORTED", LEVEL_WARNING,
                                        "AndroidManifest Exported Components Checking",
                                        """Found "exported" components(except for Launcher) for receiving outside applications' actions (AndroidManifest.xml). 
    These components can be initilized by other apps. You should add or modify the attribute to [exported="false"] if you don't want to. 
    You can also protect it with a customized permission with "signature" or higher protectionLevel and specify in "android:permission" attribute.""")

                for i in list_alerting_exposing_components_NonGoogle:
                    self.writer.write("%10s => %s" % (i[0], i[1]))

            if list_alerting_exposing_components_Google:
                self.writer.startWriter("PERMISSION_EXPORTED_GOOGLE", LEVEL_NOTICE,
                                        "AndroidManifest Exported Components Checking 2",
                                        "Found \"exported\" components(except for Launcher) for receiving Google's \"Android\" actions (AndroidManifest.xml):")

                for i in list_alerting_exposing_components_Google:
                    self.writer.write("%10s => %s" % (i[0], i[1]))
        else:
            self.writer.startWriter("PERMISSION_EXPORTED", LEVEL_INFO, "AndroidManifest Exported Components Checking",
                                    "No exported components(except for Launcher) for receiving Android or outside applications' actions (AndroidManifest.xml).")

        # ------------------------------------------------------------------------
        # "exported" checking (provider):
        # android:readPermission, android:writePermission, android:permission
        list_ready_to_check = []

        for item in utils.get_elements_by_tagname(xml, "provider"):
            name = item.attrib.get("{http://schemas.android.com/apk/res/android}name")
            exported = item.attrib.get("{http://schemas.android.com/apk/res/android}exported")
            if not exported:
                exported = ""
            if not utils.is_null_or_empty_string(name) and exported.lower() != "false":
                # exported is only "true" or non-set
                permission = item.attrib.get("{http://schemas.android.com/apk/res/android}permission")
                readPermission = item.attrib.get("{http://schemas.android.com/apk/res/android}readPermission")
                writePermission = item.attrib.get("{http://schemas.android.com/apk/res/android}writePermission")
                has_exported = True if (exported != "") else False

                list_ready_to_check.append(
                    (name, exported, permission, readPermission, writePermission, has_exported))

        list_alerting_exposing_providers_no_exported_setting = []  # providers that Did not set exported
        list_alerting_exposing_providers = []  # provider with "true" exported
        for i in list_ready_to_check:  # only exist "exported" provider or not set
            exported = i[1]
            permission = i[2]
            readPermission = i[3]
            writePermission = i[4]
            has_exported = i[5]

            is_dangerous = False
            list_perm = []
            if permission != None:
                list_perm.append(permission)
            if readPermission != None:
                list_perm.append(readPermission)
            if writePermission != None:
                list_perm.append(writePermission)

            if list_perm:  # among "permission" or "readPermission" or "writePermission", any of the permission is set
                for self_defined_permission in list_perm:  # (1)match any (2)ignore permission that is not found
                    if self_defined_permission in dangerous_custom_permissions\
                            or permission in normal_or_default_custom_permissions:
                        is_dangerous = True
                        break
                if exported == "" and self.int_target_sdk >= 17\
                        and is_dangerous:  # permission is not set, it will depend on the Android system
                    list_alerting_exposing_providers_no_exported_setting.append(i)

            else:  # none of any permission
                if exported.lower() == "true":
                    is_dangerous = True
                # if permission is not set, it will depend on the Android system
                elif exported == "" and self.int_target_sdk >= 17:
                    list_alerting_exposing_providers_no_exported_setting.append(i)

            # if exported="true" and none of the permission are set => of course dangerous
            if is_dangerous:
                list_alerting_exposing_providers.append(i)

        if list_alerting_exposing_providers or list_alerting_exposing_providers_no_exported_setting:
            if list_alerting_exposing_providers_no_exported_setting:  # providers that did not set exported

                self.writer.startWriter("PERMISSION_PROVIDER_IMPLICIT_EXPORTED", LEVEL_CRITICAL,
                                        "AndroidManifest ContentProvider Exported Checking",
                                        """We strongly suggest you explicitly specify the "exported" attribute (AndroidManifest.xml). 
    For Android "android:targetSdkVersion" < 17, the exported value of ContentProvider is "true" by default. 
    For Android "android:targetSdkVersion" >= 17, the exported value of ContentProvider is "false" by default. 
    Which means if you do not explicitly set the "android:exported", you will expose your ContentProvider to Android < 4.2 devices. 
    Even if you set the provider the permission with [protectionalLevel="normal"], other apps still cannot access it on Android >= 4.2 devices because of the default constraint. 
    Please make sure to set exported to "true" if you initially want other apps to use it (including protected by "signature" protectionalLevel), and set to "false" if your do not want to. 
    Please still specify the "exported" to "true" if you have already set the corresponding "permission", "writePermission" or "readPermission" to "signature" protectionLevel or higher
    because other apps signed by the same signature in Android >= 4.2 devices cannot access it.
    Reference: http://developer.android.com/guide/topics/manifest/provider-element.html#exported
    Vulnerable ContentProvider Case Example: 
      (1)https://www.nowsecure.com/mobile-security/ebay-android-content-provider-injection-vulnerability.html
      (2)http://blog.trustlook.com/2013/10/23/ebay-android-content-provider-information-disclosure-vulnerability/
      (3)http://www.wooyun.org/bugs/wooyun-2010-039169
    """)

                for i in list_alerting_exposing_providers_no_exported_setting:
                    self.writer.write("%10s => %s" % ("provider", i[0]))

            if list_alerting_exposing_providers:  # provider with "true" exported and not enough permission protected on it

                self.writer.startWriter("PERMISSION_PROVIDER_EXPLICIT_EXPORTED", LEVEL_CRITICAL,
                                        "AndroidManifest ContentProvider Exported Checking",
                                        """Found "exported" ContentProvider, allowing any other app on the device to access it (AndroidManifest.xml). You should modify the attribute to [exported="false"] or set at least "signature" protectionalLevel permission if you don't want to.
    Vulnerable ContentProvider Case Example: 
      (1)https://www.nowsecure.com/mobile-security/ebay-android-content-provider-injection-vulnerability.html
      (2)http://blog.trustlook.com/2013/10/23/ebay-android-content-provider-information-disclosure-vulnerability/
      (3)http://www.wooyun.org/bugs/wooyun-2010-039169""")
                for i in list_alerting_exposing_providers:
                    self.writer.write("%10s => %s" % ("provider", i[0]))

        else:
            self.writer.startWriter("PERMISSION_PROVIDER_IMPLICIT_EXPORTED", LEVEL_INFO,
                                    "AndroidManifest ContentProvider Exported Checking",
                                    "No exported \"ContentProvider\" found (AndroidManifest.xml).")

        # ------------------------------------------------------------------------
        # intent-filter checking:

        """
    		Example misconfiguration:
    			<receiver android:name=".service.push.SystemBroadcastReceiver">
    	            <intent-filter android:enabled="true" android:exported="false">
    	                <action android:name="android.intent.action.BOOT_COMPLETED" />
    	                <action android:name="android.intent.action.USER_PRESENT" />
    	            </intent-filter>
    	            <intent-filter android:enabled="true" android:exported="false">
    	            </intent-filter>
    	        </receiver>

    	    Detected1: <intent-filter android:enabled="true" android:exported="false">
    	    Detected2: No actions in "intent-filter"
    	"""

        find_tags = ["activity", "activity-alias", "service", "receiver"]
        list_wrong_intent_filter_settings = []
        list_no_actions_in_intent_filter = []
        for tag in find_tags:
            for item in utils.get_elements_by_tagname(xml, tag):
                isDetected1 = False
                isDetected2 = False
                for ssitem in utils.get_elements_by_tagname(item, "intent-filter"):
                    if (ssitem.attrib.get("{http://schemas.android.com/apk/res/android}enabled") != None) or (
                            ssitem.attrib.get("{http://schemas.android.com/apk/res/android}exported") != None):
                        isDetected1 = True
                    if len(utils.get_elements_by_tagname(item, "action")) == 0:
                        isDetected2 = True
                if isDetected1:
                    list_wrong_intent_filter_settings.append(
                        (tag, item.attrib.get("{http://schemas.android.com/apk/res/android}name")))
                if isDetected2:
                    list_no_actions_in_intent_filter.append(
                        (tag, item.attrib.get("{http://schemas.android.com/apk/res/android}name")))

        if list_wrong_intent_filter_settings or list_no_actions_in_intent_filter:
            if list_wrong_intent_filter_settings:
                self.writer.startWriter("PERMISSION_INTENT_FILTER_MISCONFIG", LEVEL_WARNING,
                                        "AndroidManifest \"intent-filter\" Settings Checking",
                                        """Misconfiguration in "intent-filter" of these components (AndroidManifest.xml). 
    Config "intent-filter" should not have "android:exported" or "android:enabled" attribute. 
    Reference: http://developer.android.com/guide/topics/manifest/intent-filter-element.html
    """)
                for tag, name in list_wrong_intent_filter_settings:
                    self.writer.write("%10s => %s" % (tag, name))

            if list_no_actions_in_intent_filter:
                self.writer.startWriter("PERMISSION_INTENT_FILTER_MISCONFIG", LEVEL_CRITICAL,
                                        "AndroidManifest \"intent-filter\" Settings Checking",
                                        """Misconfiguration in "intent-filter" of these components (AndroidManifest.xml).
    Config "intent-filter" should have at least one "action".
    Reference: http://developer.android.com/guide/topics/manifest/intent-filter-element.html
    """)
                for tag, name in list_no_actions_in_intent_filter:
                    self.writer.write("%10s => %s" % (tag, name))
        else:
            self.writer.startWriter("PERMISSION_INTENT_FILTER_MISCONFIG", LEVEL_INFO,
                                    "AndroidManifest \"intent-filter\" Settings Checking",
                                    "\"intent-filter\" of AndroidManifest.xml check OK.")

        # ------------------------------------------------------------------------
        # Implicit Service (** Depend on: "exported" checking (activity, activity-alias, service, receiver) **)

        if list_implicit_service_components:
            self.writer.startWriter("PERMISSION_IMPLICIT_SERVICE", LEVEL_CRITICAL, "Implicit Service Checking",
                                    """To ensure your app is secure, always use an explicit intent when starting a Service and DO NOT declare intent filters for your services. Using an implicit intent to start a service is a security hazard because you cannot be certain what service will respond to the intent, and the user cannot see which service starts. 
    Reference: http://developer.android.com/guide/components/intents-filters.html#Types""", ["Implicit_Intent"])

            for name in list_implicit_service_components:
                self.writer.write("=> %s" % name)

        else:
            self.writer.startWriter("PERMISSION_IMPLICIT_SERVICE", LEVEL_INFO, "Implicit Service Checking",
                                    "No dangerous implicit service.", ["Implicit_Intent"])
