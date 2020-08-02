import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Check if application has detection for installation source (e.g Google Play or F-Droid)"
    tags = ["HACKER_INSTALL_SOURCE_CHECK"]

    def analyze(self) -> None:

        path_get_installer_package_name = self.analysis.find_methods(
            "Landroid/content/pm/PackageManager;", "getInstallerPackageName", "\(Ljava/lang/String;\)Ljava/lang/String;")
        path_get_installer_package_name = staticDVM.get_paths(path_get_installer_package_name)

        if path_get_installer_package_name:
            self.writer.startWriter("HACKER_INSTALL_SOURCE_CHECK", LEVEL_NOTICE, "APK Installing Source Checking",
                               "This app has code checking APK installer sources(e.g. from Google Play, from Amazon, "
                               "etc.). It might be used to check for whether the app is hacked by the attackers.",
                               ["Hacker"])
            # self.writer.show_xrefs_method_class_analysis_list(path_get_installer_package_name)
            self.writer.show_Paths(path_get_installer_package_name)
        else:
            self.writer.startWriter("HACKER_INSTALL_SOURCE_CHECK", LEVEL_INFO, "APK Installing Source Checking",
                               "Did not detect this app checks for APK installer sources.", ["Hacker"])
