from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks if debug mode is enabled"

    def analyze(self) -> None:
        # DEBUGGABLE checking:
        is_debug_open = self.apk.get_attribute_value('application', 'debuggable') not in (None, "false")
        if is_debug_open:
            self.writer.startWriter("DEBUGGABLE", LEVEL_CRITICAL, "Android Debug Mode Checking",
                                    "DEBUG mode is ON(android:debuggable=\"true\") in AndroidManifest.xml. This is very dangerous. The attackers will be able to sniffer the debug messages by Logcat. Please disable the DEBUG mode if it is a released application.",
                                    ["Debug"])

        else:
            self.writer.startWriter("DEBUGGABLE", LEVEL_INFO, "Android Debug Mode Checking",
                                    "DEBUG mode is OFF(android:debuggable=\"false\") in AndroidManifest.xml.",
                                    ["Debug"])

        # DEBUGGABLE_CERT checking:
        for cert in self.apk.get_certificates():
            if "Common Name: Android Debug" in cert.issuer.human_friendly:
                self.writer.startWriter("HACKER_DEBUGGABLE_CERT", LEVEL_CRITICAL, "Android Debug Certificate Checking",
                                        "App is signed with debug certificate, indicating that debug mode may be enabled. This could potentially be dangerous if used in production environments.",
                                        ["Debug"])
                return

        self.writer.startWriter("HACKER_DEBUGGABLE_CERT", LEVEL_INFO, "Android Debug Certificate Checking",
                                "App is signed with a production certificate. This is good.",
                                ["Debug"])


# # Checking whether the app is checking debuggable: #TODO maybe implement this since it returns other results than HACKER DEBUGGABLE CERT
#
# """
# 	Java code checking debuggable:
# 		boolean isDebuggable = (0 != (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE));
# 		if (isDebuggable) { }
# 	Smali code checking debuggable:
# 		invoke-virtual {p0}, Lcom/example/androiddebuggable/MainActivity;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;
# 		move-result-object v1
# 		iget v1, v1, Landroid/content/pm/ApplicationInfo;->flags:I
# 		and-int/lit8 v1, v1, 0x2
# 		if-eqz v1, :cond_0
# 	Checking Pattern:
# 		1. Find tainted calling field: Landroid/content/pm/ApplicationInfo;->flags:I
# 		2. Get the next instruction of the calling field: Landroid/content/pm/ApplicationInfo;->flags:I
# 		3. Check whether the next instruction is 0xDD(and-int/lit8) and make sure the register numbers are all matched
# 			iget [[v1]], v1, [[[Landroid/content/pm/ApplicationInfo;->flags:I]]]
# 			and-int/lit8 v1, [[v1]], [0x2]
# """
# list_detected_FLAG_DEBUGGABLE_path = []
# field_ApplicationInfo_flags_debuggable = vmx.get_tainted_field("Landroid/content/pm/ApplicationInfo;", "flags", "I")
#
# if field_ApplicationInfo_flags_debuggable:
#     for path, stack in field_ApplicationInfo_flags_debuggable.get_paths_and_stacks(d,
#                                                                                    filteringEngine.get_filtering_regexp()):
#         last_one_ins = stack.gets()[-1]
#         last_two_ins = stack.gets()[-2]
#
#         if (last_one_ins is not None) and (last_two_ins is not None):
#             try:
#                 if (last_one_ins[0] == 0xDD) and (last_two_ins[1][0][1] == last_one_ins[1][1][1]) and (
#                         last_one_ins[1][2][1] == 2):  # and-int/lit8 vx,vy,lit8
#                     list_detected_FLAG_DEBUGGABLE_path.append(path)
#                 """
#                     Example 1:
#                         last_two_ins => [82, [(0, 1), (0, 1), (258, 16, 'Landroid/content/pm/ApplicationInfo;->flags I')]]
#                         last_one_ins => [221, [(0, 1), (0, 1), (1, 2)]]
#                     Example 2:
#                         last_two_ins => [82, [(0, 2), (0, 0), (258, 896, 'Landroid/content/pm/ApplicationInfo;->flags I')]]
#                         last_one_ins => [221, [(0, 2), (0, 2), (1, 2)]]
#                     Java code:
#                         stack.show()
#                         print(last_one_ins)
#                         print(last_two_ins)
#                 """
#             except:
#                 pass
#
# if list_detected_FLAG_DEBUGGABLE_path:
#     writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_NOTICE, "Codes for Checking Android Debug Mode",
#                        "Found codes for checking \"ApplicationInfo.FLAG_DEBUGGABLE\" in AndroidManifest.xml:",
#                        ["Debug", "Hacker"])
#
#     for path in list_detected_FLAG_DEBUGGABLE_path:
#         writer.show_single_PathVariable(d, path)
# else:
#     writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_INFO, "Codes for Checking Android Debug Mode",
#                        "Did not detect codes for checking \"ApplicationInfo.FLAG_DEBUGGABLE\" in AndroidManifest.xml.",
#                        ["Debug", "Hacker"])
