import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks adb backup"
    tags = ["ALLOW_BACKUP"]

    def analyze(self) -> None:
        # Adb Backup check

        if self.apk.get_attribute_value("application", "allowBackup") in ("true", None):
            self.writer.startWriter("ALLOW_BACKUP", LEVEL_NOTICE, "AndroidManifest Adb Backup Checking",
                               """ADB Backup is ENABLED for this app (default: ENABLED). ADB Backup is a good tool for backing up all of your files. If it's open for this app, people who have your phone can copy all of the sensitive data for this app in your phone (Prerequisite: 1.Unlock phone's screen 2.Open the developer mode). The sensitive data may include lifetime access token, username or password, etc.
    Security case related to ADB Backup:
    1.http://www.securityfocus.com/archive/1/530288/30/0/threaded
    2.http://blog.c22.cc/advisories/cve-2013-5112-evernote-android-insecure-storage-of-pin-data-bypass-of-pin-protection/
    3.http://nelenkov.blogspot.co.uk/2012/06/unpacking-android-backups.html
    Reference: http://developer.android.com/guide/topics/manifest/application-element.html#allowbackup
    """)
        else:
            self.writer.startWriter("ALLOW_BACKUP", LEVEL_INFO, "AndroidManifest Adb Backup Checking",
                               "This app has disabled Adb Backup.")