from vector_base import VectorBase
from constants import *
from androguard.core.bytecodes import dvm
from timeit import default_timer as timer

class Vector(VectorBase):
    description = "Checks if debug mode is enabled, " \
                  "if a debug certificate is present, and " \
                  "if debug mode detection is used"
    tags = ["DEBUGGABLE", "HACKER_DEBUGGABLE_CERT", "HACKER_DEBUGGABLE_CHECK"]

    OPCODES = {
        "iget": 0x52,
        "and-int/lit8": 0xDD,
    }

    def analyze(self) -> None:
        self.check_is_debuggable()
        self.check_has_debuggable_certificate()
        self.check_detects_debuggable()

    def check_is_debuggable(self) -> None:
        is_debug_open = self.apk.get_attribute_value('application', 'debuggable') not in (None, "false")
        if is_debug_open:
            self.writer.startWriter("DEBUGGABLE", LEVEL_CRITICAL, "Android Debug Mode Checking",
                                    "DEBUG mode is ON(android:debuggable=\"true\") in AndroidManifest.xml. This is very dangerous. The attackers will be able to sniffer the debug messages by Logcat. Please disable the DEBUG mode if it is a released application.",
                                    ["Debug"])

        else:
            self.writer.startWriter("DEBUGGABLE", LEVEL_INFO, "Android Debug Mode Checking",
                                    "DEBUG mode is OFF(android:debuggable=\"false\") in AndroidManifest.xml.",
                                    ["Debug"])

    def check_has_debuggable_certificate(self) -> None:
        for cert in self.apk.get_certificates():
            if "Common Name: Android Debug" in cert.issuer.human_friendly:
                self.writer.startWriter("HACKER_DEBUGGABLE_CERT", LEVEL_CRITICAL, "Android Debug Certificate Checking",
                                        "App is signed with debug certificate, indicating that debug mode may be enabled. This could potentially be dangerous if used in production environments.",
                                        ["Debug"])
                return

        self.writer.startWriter("HACKER_DEBUGGABLE_CERT", LEVEL_INFO, "Android Debug Certificate Checking",
                                "App is signed with a production certificate. This is good.",
                                ["Debug"])

    # See also: https://web.archive.org/web/20200726122505/http://izvornikod.com/Blog/tabid/82/EntryId/13/How-to
    # -check-if-your-android-application-is-running-in-debug-or-release-mode.aspx
    def check_detects_debuggable(self) -> None:

        start = timer()
        matches = self._scan_for_debuggable_checks()
        end = timer()
        self.writer.writeInf_ForceNoPrint("time_hacker_debuggable_check", end-start)

        if matches:
            self.writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_NOTICE,
                                    "Codes for Checking Android Debug Mode",
                                    "Detected code that checks whether debug mode is enabled in:",
                                    ["Debug", "Hacker"])

            for method in matches:
                self.writer.write(
                    "%s->%s%s" % (method.get_class_name(), method.get_name(), method.get_descriptor()))
            return

        self.writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_INFO, "Code for Checking Android Debug Mode",
                                "Did not detect code that checks whether debug mode is enabled",
                                ["Debug", "Hacker"])

    def _scan_for_debuggable_checks(self):
        """
            Java code checking debuggable:
                    boolean isDebuggable = (0 != (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE));
                    if (isDebuggable) { }

                Smali code checking debuggable:
                    invoke-virtual {p0}, Lcom/example/androiddebuggable/MainActivity;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;
                    move-result-object v1
                    iget v1, v1, Landroid/content/pm/ApplicationInfo;->flags:I
                    and-int/lit8 v1, v1, 0x2
                    if-eqz v1, :cond_0

                Checking Pattern:
                    1. Find tainted calling field: Landroid/content/pm/ApplicationInfo;->flags:I
                    2. Get the next instruction of the calling field: Landroid/content/pm/ApplicationInfo;->flags:I
                    3. Check whether the next instruction is 0xDD(and-int/lit8) and make sure the register numbers are all matched
                        iget [[v1]], v1, [[[Landroid/content/pm/ApplicationInfo;->flags:I]]]
                        and-int/lit8 v1, [[v1]], [0x2]
        """
        # Do a quick scan to detect if there are any Landroid/content/pm/ApplicationInfo;->flags fields present,
        # saving time if there are no such fields in the application
        if not any([dalvik for dalvik in self.dalvik
                    if any([i for i in dalvik.get_all_fields()
                                if i.get_list() == ['Landroid/content/pm/ApplicationInfo;', 'I', 'flags']
                            ])
                   ]):
            return []

        # Loop over all methods and retrieve methods that contain ApplicationInfo;->flags fields and access its debug flag
        # List comprehensions are used for performance purposes
        return [method_analysis.get_method()
                for method_analysis in self.analysis.get_methods()
                    if not method_analysis.is_external() and \
                        self._scan_method_instructions_for_application_info(method_analysis.get_method().get_instructions())
                ]

    def _scan_method_instructions_for_application_info(self, instructions):
        """
        Returns if there any instructions that access ApplicationInfo;->flags fields and subsequently access its debug flag
        """
        return any([True
                    for instruction in instructions
                        if instruction.get_op_value() == self.OPCODES["iget"] and \
                            instruction.get_operands()[2][2] == "Landroid/content/pm/ApplicationInfo;->flags I" and \
                            self._does_next_instruction_access_debug_flag(instruction.get_operands()[0], next(instructions))
                    ])

    def _does_next_instruction_access_debug_flag(self, flags_register, instruction):
        """
        Checks if the instruction accesses the debug flag in the register that contains ApplicationInfo;->flags
        """
        operands = instruction.get_operands()
        opcode = instruction.get_op_value()
        if opcode == self.OPCODES["and-int/lit8"] and \
                operands[2] == (dvm.OPERAND_LITERAL, 2) and \
                operands[1] == flags_register:
            return True
        return False