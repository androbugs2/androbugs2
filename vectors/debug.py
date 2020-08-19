from vector_base import VectorBase
from constants import *
from androguard.core.bytecodes import dvm


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
        debuggable_check_paths = []
        application_info_methods = list(self.analysis.find_methods(methodname="getApplicationInfo",
                                                                   classname="Landroid/content/pm/PackageManager;"))
        application_info_methods.extend(list(self.analysis.find_methods(methodname="getApplicationInfo",
                                                                        classname="Landroid/content/Context;")))

        matches = []

        if application_info_methods:
            xrefs = []
            for method in application_info_methods:
                xrefs.extend(method.get_xref_from())

            for _, method, _ in xrefs:
                if self._scan_xrefs_for_debuggable_checks(method):
                    matches.append(method)

        if matches or self.analysis.is_class_present("Lcom/google/android/gms/common/GoogleSignatureVerifier;"):
            self.writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_NOTICE,
                                    "Codes for Checking Android Debug Mode",
                                    "Detected code that checks whether debug mode is enabled in:",
                                    ["Debug", "Hacker"])
            if self.analysis.is_class_present("Lcom/google/android/gms/common/GoogleSignatureVerifier;"):
                self.writer.write("Lcom/google/android/gms/common/GoogleSignatureVerifier;")

            for method in matches:
                self.writer.write(
                    "%s->%s%s" % (method.get_class_name(), method.get_name(), method.get_descriptor()))
            return

        self.writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_INFO, "Code for Checking Android Debug Mode",
                                "Did not detect code that checks whether debug mode is enabled",
                                ["Debug", "Hacker"])

    def _scan_xrefs_for_debuggable_checks(self, method):
        flags_variable = None
        for instruction in method.get_instructions():
            operands = instruction.get_operands()
            opcode = instruction.get_op_value()
            if len(operands) == 3:
                if flags_variable is None and opcode == self.OPCODES["iget"]:
                    if operands[2][0] == (dvm.OPERAND_KIND + dvm.KIND_FIELD) \
                            and operands[2][2] == "Landroid/content/pm/ApplicationInfo;->flags I":
                        flags_variable = operands[0]
                        continue
                if flags_variable and opcode == self.OPCODES["and-int/lit8"]:
                    if operands[2] == (dvm.OPERAND_LITERAL, 2) \
                            and operands[0] == flags_variable and operands[1] == flags_variable:
                        return True
        return False
