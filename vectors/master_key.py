from vector_base import VectorBase
from constants import *
from engines import *

class Vector(VectorBase):
    description = "Checks Master Key Type I Vulnerability "

    def analyze(self) -> None:
        # Master Key Vulnerability checking:

        all_files = self.apk.get_files()
        for f in all_files:
            if f == 'classes.dex':
                self.writer.startWriter("MASTER_KEY", LEVEL_CRITICAL, "Master Key Type I Vulnerability",
                                        "This APK is suffered from Master Key Type I Vulnerability.", None,
                                        "CVE-2013-4787")
                return

        self.writer.startWriter("MASTER_KEY", LEVEL_INFO, "Master Key Type I Vulnerability",
                               "No Master Key Type I Vulnerability in this APK.", None, "CVE-2013-4787")
