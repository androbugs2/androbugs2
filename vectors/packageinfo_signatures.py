from engines import FilteringEngine
from vector_base import VectorBase
from constants import *

class Vector(VectorBase):
    description = "Checks Master Key Type I Vulnerability "

    def analyze(self) -> None:
        # Android PackageInfo signatures checking:

        """
            Example:

                move-result-object v0
                iget-object v2, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

                PackageManager pkgManager = context.getPackageManager();
                pkgManager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES).signatures[0].toByteArray();
        """

        list_PackageInfo_signatures = []
        path_PackageInfo_signatures = self.analysis.find_methods(
            "Landroid/content/pm/PackageManager;", "getPackageInfo",
            "(Ljava/lang/String; I)Landroid/content/pm/PackageInfo;")  # TODO might be changed due to Android Support library -> androidX
        path_PackageInfo_signatures = self.filtering_engine.filter_list_of_paths(self.dalvik,
                                                                           path_PackageInfo_signatures)  # TODO fix filtering
        for i in self.analysis.trace_Register_value_by_Param_in_source_Paths(self.dalvik, path_PackageInfo_signatures):
            if i.getResult()[2] is None:
                continue
            if i.getResult()[2] == 64:
                list_PackageInfo_signatures.append(i.getPath())

        if list_PackageInfo_signatures:
            self.writer.startWriter("HACKER_SIGNATURE_CHECK", LEVEL_NOTICE, "Getting Signature Code Checking",
                               "This app has code checking the package signature in the code. It might be used to check for whether the app is hacked by the attackers.",
                               ["Signature", "Hacker"])
            for signature in list_PackageInfo_signatures:
                self.writer.show_Path(self.dalvik, signature)
        else:
            self.writer.startWriter("HACKER_SIGNATURE_CHECK", LEVEL_INFO, "Getting Signature Code Checking",
                               "Did not detect this app is checking the signature in the code.",
                               ["Signature", "Hacker"])
