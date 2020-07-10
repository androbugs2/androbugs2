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
        if any([self.check_xamarin(),
                self.check_flutter(),
                self.check_react_native(),
                self.check_ijiami(),
                self.check_bangcle()]):
            return
        else:
            self.writer.startWriter("FRAMEWORK",
                                    LEVEL_INFO,
                                    "App framework identification",
                                    "No frameworks detected (checking for Xamarin, Flutter, React Native).",
                                    ['Framework'])

    def check_xamarin(self) -> bool:
        mono_pm = self.analysis.get_method_analysis_by_name(self.xamarin_signature["class_name"],
                                                            self.xamarin_signature["method_name"],
                                                            self.xamarin_signature["method_descriptor"])
        if mono_pm is None:
            return False

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
                    return True
        return False

    def check_flutter(self) -> None:
        pass

    def check_react_native(self) -> None:
        pass

    def check_ijiami(self) -> bool:
        if any(self.analysis.find_methods("Lcom/shell/NativeApplication;", "load",
                                          "(Landroid/app/Application; Ljava/lang/String;)Z")):
            self.writer.startWriter("FRAMEWORK",
                                    LEVEL_NOTICE,
                                    "App framework identification",
                                    "This app is using Ijiami Encryption Framework (http://www.ijiami.cn/)."
                                    "Please send your unencrypted apk instead so that we can check thoroughly.",
                                    ['Framework'])
            return True
        return False

    def check_bangcle(self) -> bool:
        if any(self.analysis.find_methods("Lcom/secapk/wrapper/ACall;",
                                          "getACall",
                                          "()Lcom/secapk/wrapper/ACall;")):
            self.writer.startWriter("FRAMEWORK",
                                    LEVEL_NOTICE,
                                    "App framework identification",
                                    "This app is using Bangcle Encryption Framework (http://www.bangcle.com/)."
                                    "Please send your unencrypted apk instead so that we can check thoroughly.",
                                    ['Framework'])
            return True
        return False

