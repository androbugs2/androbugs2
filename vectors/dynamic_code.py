import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks Detect dynamic code loading"

    def analyze(self) -> None:
        # Detect dynamic code loading

        paths_DexClassLoader = self.analysis.find_methods("Ldalvik/system/DexClassLoader;")
        paths_DexClassLoader = self.filtering_engine.filter_method_class_analysis_list(paths_DexClassLoader)
        if paths_DexClassLoader:
            self.writer.startWriter("DYNAMIC_CODE_LOADING", LEVEL_WARNING, "Dynamic Code Loading",
                               "Dynamic code loading(DexClassLoader) found:")
            self.writer.show_Paths(self.dalvik, paths_DexClassLoader)
        else:
            self.writer.startWriter("DYNAMIC_CODE_LOADING", LEVEL_INFO, "Dynamic Code Loading",
                               "No dynamic code loading(DexClassLoader) found.")