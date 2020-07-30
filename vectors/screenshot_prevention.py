import staticDVM
from vector_base import VectorBase
from constants import *
from engines import *

class Vector(VectorBase):
    description = "Developers preventing screenshot capturing checking"
    tags = ["HACKER_PREVENT_SCREENSHOT_CHECK"]

    def analyze(self) -> None:
        """
            Example:
                const/16 v1, 0x2000
                invoke-super {p0, p1}, Landroid/support/v7/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V
                invoke-virtual {p0}, Lcom/example/preventscreencapture/MainActivity;->getWindow()Landroid/view/Window;
                move-result-object v0
                invoke-virtual {v0, v1, v1}, Landroid/view/Window;->setFlags(II)V


                getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        """

        list_code_for_preventing_screen_capture = []
        path_code_for_preventing_screen_capture = self.analysis.find_methods(
            "Landroid/view/Window;", "setFlags",
            "\(I I\)V")  # TODO might be changed due to Android Support library -> androidX
        for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(path_code_for_preventing_screen_capture):
            if (i.getResult()[1] is None) or (i.getResult()[2] is None):
                continue
            if (not isinstance(i.getResult()[1], int)) or (not isinstance(i.getResult()[2], int)):
                continue
            if (i.getResult()[1] & 0x2000) and (i.getResult()[2] & 0x2000):
                list_code_for_preventing_screen_capture.append(i.getPath())

        if list_code_for_preventing_screen_capture:
            self.writer.startWriter("HACKER_PREVENT_SCREENSHOT_CHECK", LEVEL_NOTICE,
                                    "Code Setting Preventing Screenshot Capturing",
                                    ("This app has code setting the preventing screenshot capturing.\n"
                                     "         Example: getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);\n"
                                     "         It is used by the developers to protect the app:"), ["Hacker"])
            for interesting_code in list_code_for_preventing_screen_capture:
                self.writer.show_Path(interesting_code)
        else:
            self.writer.startWriter("HACKER_PREVENT_SCREENSHOT_CHECK", LEVEL_INFO,
                               "Code Setting Preventing Screenshot Capturing",
                               "Did not detect this app has code setting preventing screenshot capturing.", ["Hacker"])

