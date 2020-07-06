from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks if debug mode is enabled"

    def analyze(self) -> None:
        return None

# TODO implement this vector
# addSearchItem params: (1)match_id  (2)regex or string(url or string you want to find), (3)is using regex for parameter 2
# efficient_string_search_engine.addSearchItem("$__possibly_check_root__", re.compile("/system/bin"),
#                                              True)  # "root" checking
# efficient_string_search_engine.addSearchItem("$__possibly_check_su__", "su", False)  # "root" checking2
# efficient_string_search_engine.addSearchItem("$__sqlite_encryption__", re.compile("PRAGMA\s*key\s*=", re.I),
#                                              True)  # SQLite encryption checking
