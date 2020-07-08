import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks runtime exec"

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

        list_runtime_exec = []

        path_runtime_exec = self.analysis.find_methods("Ljava/lang/Runtime;", "exec",
                                                       "(Ljava/lang/String;)Ljava/lang/Process;")
        path_runtime_exec = self.filtering_engine.filter_list_of_paths(self.dalvik, path_runtime_exec)

        for i in staticDVM.trace_register_value_by_param_in_source_paths(self.dalvik, self.analysis, path_runtime_exec):
            if i.getResult()[1] is None:
                continue
            if i.getResult()[1] == "su":
                list_runtime_exec.append(i.getPath())

        if path_runtime_exec:
            self.writer.startWriter("COMMAND", LEVEL_CRITICAL, "Runtime Command Checking",
                                    "This app is using critical function 'Runtime.getRuntime().exec(\"...\")'.\nPlease confirm these following code secions are not harmful:",
                                    ["Command"])

            self.writer.show_Paths(self.dalvik, path_runtime_exec)

            if list_runtime_exec:
                self.writer.startWriter("COMMAND_SU", LEVEL_CRITICAL, "Runtime Critical Command Checking",
                                        "Requesting for \"root\" permission code sections 'Runtime.getRuntime().exec(\"su\")' found (Critical but maybe false positive):",
                                        ["Command"])

                for path in list_runtime_exec:
                    self.writer.show_Path(self.dalvik, path)
            else:
                self.writer.startWriter("COMMAND", LEVEL_INFO, "Runtime Command Checking",
                                        "This app is not using critical function 'Runtime.getRuntime().exec(\"...\")'.",
                                        ["Command"])
