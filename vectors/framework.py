from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks if a framework was used to develop the app, and if so, which one."

    xamarin_signature = {
        "class_name": "Lmono/MonoPackageManager;",
        "method_name": "LoadApplication",
        "method_descriptor": "(Landroid/content/Context; Landroid/content/pm/ApplicationInfo; [Ljava/lang/String;)V",
    }

    def analyze(self) -> None:
        self.check_xamarin()

    def check_xamarin(self) -> None:
        mono_pm = self.analysis.get_method_analysis_by_name(self.xamarin_signature["class_name"],
                                                            self.xamarin_signature["method_name"],
                                                            self.xamarin_signature["method_descriptor"])

        em = mono_pm.get_method()
        for idx, ins in enumerate(em.get_instructions()):
            if ins.get_name() == "const-string" and ins.get_output() == "v0, 'xamarin-app'":
                ins_next = em.get_instruction(idx + 1)
                if ins_next.get_name() == "invoke-static" \
                        and ins_next.get_output() == "v0, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V":
                    self.writer.startWriter("FRAMEWORK",
                                            LEVEL_NOTICE,
                                            "App framework identification",
                                            "Application depends on Xamarin framework (library detected). "
                                            "For more information about Xamarin, see: "
                                            "https://dotnet.microsoft.com/apps/xamarin.",
                                            ['Framework'])
                    return
