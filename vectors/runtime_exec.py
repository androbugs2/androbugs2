import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks runtime exec"
    tags = ["COMMAND", "COMMAND_SU"]

    def analyze(self) -> None:
        # Runtime exec checking:

        """
            Example Java code:
                1. Runtime.getRuntime().exec("");
                2. Runtime rr = Runtime.getRuntime(); Process p = rr.exec("ls -al");

            Example Bytecode code (The same bytecode for those two Java code):
                const-string v2, "ls -al"
                invoke-virtual {v1, v2}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
        """

        paths_runtime_exec_su = []

        path_runtime_exec = list(self.analysis.find_methods("Ljava/lang/Runtime;", "exec", "\(Ljava/lang/String;\)Ljava/lang/Process;"))

        for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(path_runtime_exec):
            if i.getResult()[1] is None or isinstance(i.getResult()[1], staticDVM.RegisterAnalyzerVMClassContainer):
                continue
            if i.getResult()[1].startswith("su"):
                paths_runtime_exec_su.append(i.getPath())

        path_runtime_exec = staticDVM.get_paths(path_runtime_exec)

        if path_runtime_exec:
            self.writer.startWriter("COMMAND", LEVEL_CRITICAL, "Runtime Command Checking",
                                    "This app is using critical function 'Runtime.getRuntime().exec("
                                    "\"...\")'.\nPlease confirm these following code secions are not harmful:",
                                    ["Command"])

            self.writer.show_Paths(path_runtime_exec)

            if paths_runtime_exec_su:
                self.writer.startWriter("COMMAND_SU", LEVEL_CRITICAL, "Runtime Critical Command Checking",
                                        "Requesting for \"root\" permission code sections 'Runtime.getRuntime().exec("
                                        "\"su\")' found (Critical but maybe false positive):",
                                        ["Command"])

                self.writer.show_Paths(paths_runtime_exec_su)
        else:
            self.writer.startWriter("COMMAND", LEVEL_INFO, "Runtime Command Checking",
                                    "This app is not using critical function 'Runtime.getRuntime().exec(\"...\")'.",
                                    ["Command"])
