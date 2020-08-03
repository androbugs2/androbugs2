import constants
from vector_base import VectorBase
from constants import *
from engines import *
import utils
import base64

class Vector(VectorBase):
    description = "Here is a description of the vector(s) that are checked within this class"
    tags = ["EXAMPLE_VECTOR"] # list of tags that are checked within this class

    def analyze(self) -> None:

        # use androguards analysis object to look for objects in the apk
        found_methods = self.analysis.find_methods()
        # for each caller XREF in the found methods, make a separate entry in the list
        list_of_paths = staticDVM.get_paths(found_methods)

        if list_of_paths:
            self.writer.startWriter("EXAMPLE_VECTOR", LEVEL_CRITICAL,
                                    "Example vector check",
                                    "Example vector description"
                                    ["Example_Vector_Category"])
            self.writer.show_Paths(list_of_paths)
        else:
            self.writer.startWriter("EXAMPLE_VECTOR", LEVEL_CRITICAL,
                                    "Example vector check",
                                    "Example vector description"
                                    ["Example_Vector_Category"])

