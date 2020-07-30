import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks Detect dynamic code loading"
    tags = ["DYNAMIC_CODE_LOADING"]
    def analyze(self) -> None:
        # Detect dynamic code loading

        paths_dex_class_loader_method_analysis_list = self.analysis.find_methods("Ldalvik/system/DexClassLoader;")
        paths_dex_class_loader_method_analysis_list = self.filtering_engine.filter_method_class_analysis_list(paths_dex_class_loader_method_analysis_list)
        if paths_dex_class_loader_method_analysis_list:
            self.writer.startWriter("DYNAMIC_CODE_LOADING", LEVEL_WARNING, "Dynamic Code Loading",
                               "Dynamic code loading(DexClassLoader) found:")
            self.writer.show_xrefs_method_class_analysis_list(paths_dex_class_loader_method_analysis_list)
        else:
            self.writer.startWriter("DYNAMIC_CODE_LOADING", LEVEL_INFO, "Dynamic Code Loading",
                               "No dynamic code loading(DexClassLoader) found.")