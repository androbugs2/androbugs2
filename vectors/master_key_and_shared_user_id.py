from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks Master Key Type I Vulnerability and sharedUserId"
    tags = ["MASTER_KEY", "SHARED_USER_ID"]

    def has_master_key_vulnerability(self) -> bool:
        all_files = self.apk.get_files()
        found_dexfiles = 0

        for f in all_files:
            if f == 'classes.dex':
                found_dexfiles += 1

        if found_dexfiles > 1:
            self.writer.startWriter("MASTER_KEY", LEVEL_NOTICE,
                                    "Master Key Type I Vulnerability (Android 1.6 Donut through 4.2 Jelly Bean)",
                                    "This APK is suffered from Master Key Type I Vulnerability.", None,
                                    "CVE-2013-4787")
            return True

        self.writer.startWriter("MASTER_KEY", LEVEL_INFO, "Master Key Type I Vulnerability",
                                "No Master Key Type I Vulnerability in this APK.", None, "CVE-2013-4787")
        return False

    def has_shared_user_id(self) -> bool:
        sharedUserId = self.apk.get_attribute_value("manifest", "sharedUserId")

        if sharedUserId == "android.uid.system":
            self.writer.startWriter("SHARED_USER_ID", LEVEL_NOTICE, "AndroidManifest sharedUserId Checking",
                                    "This app uses \"android.uid.system\" sharedUserId, which requires the \"system("
                                    "uid=1000)\" permission. It must be signed with manufacturer's keystore or Google's "
                                    "keystore to be successfully installed on users' devices.",
                                    ["System"])
            return True
        else:
            self.writer.startWriter("SHARED_USER_ID", LEVEL_INFO, "AndroidManifest sharedUserId Checking",
                                    "This app does not use \"android.uid.system\" sharedUserId.", ["System"])
            return False

    def analyze(self) -> None:
        # System shared_user_id + Master Key Vulnerability checking: (Depends on "Master Key Vulnerability checking")
        has_master_key_vulnerability = self.has_master_key_vulnerability()
        has_shared_user_id = self.has_shared_user_id()
        if has_master_key_vulnerability and has_shared_user_id:
            self.writer.startWriter("MASTER_KEY_SYSTEM_APP", LEVEL_CRITICAL,
                                    "Rooting System with Master Key Vulnerability",
                                    "This app is malware, which requests \"system(uid=1000)\" privilege with Master "
                                    "Key vulnerability, leading the devices to be rooted.")
