import staticDVM
from engines import FilteringEngine
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks Master Key Type I Vulnerability "
    tags = ["HACKER_SIGNATURE_CHECK"]
    def analyze(self) -> None:
        # Android PackageInfo signatures checking:

        """
            Example:

                move-result-object v0
                iget-object v2, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

                PackageManager pkgManager = context.getPackageManager();
                pkgManager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES).signatures[0].toByteArray();
        """

        list_package_info_signatures = []
        path_package_info_signatures = self.analysis.find_methods(
            "Landroid/content/pm/PackageManager;", "getPackageInfo",
            "\(Ljava/lang/String; I\)Landroid/content/pm/PackageInfo;")  # TODO might be changed due to Android Support library -> androidX
        for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(
                                                                         path_package_info_signatures):
            if i.getResult()[2] is None:
                continue
            if i.getResult()[2] == 64:
                list_package_info_signatures.append(i.getPath())

        if list_package_info_signatures:
            self.writer.startWriter("HACKER_SIGNATURE_CHECK", LEVEL_NOTICE, "Getting Signature Code Checking",
                                    "This app has code checking the package signature in the code. It might be used to "
                                    "check for whether the app is hacked by the attackers.",
                                    ["Signature", "Hacker"])
            self.writer.show_Paths(list_package_info_signatures)
        else:
            self.writer.startWriter("HACKER_SIGNATURE_CHECK", LEVEL_INFO, "Getting Signature Code Checking",
                                    "Did not detect this app is checking the signature in the code.",
                                    ["Signature", "Hacker"])
