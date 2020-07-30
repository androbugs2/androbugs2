from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks for Strandhogg 2.0 vulnerability"
    tags = ["STRANDHOGG_2"]
    LAUNCH_MODES = {
        "standard": 0,
        "singleTop": 1,
        "singleTask": 2,
        "singleInstance": 3,
    }

    def check_strandhogg2(self) -> None:
        found = False
        activities_launch_mode = self.apk.get_all_attribute_value("activity", "launchMode")
        for activity in activities_launch_mode:
            if activity.endswith((str(self.LAUNCH_MODES["standard"]), str(self.LAUNCH_MODES["singleTop"]))):
                found = True
                break

        if found or not activities_launch_mode:
            self.writer.startWriter("STRANDHOGG_2",
                                    LEVEL_CRITICAL,
                                    "Standhogg 2.0",
                                    "This application is vulnerable to the Standhogg 2.0 vulnerability. "
                                    "Please set activity launchModes to 'singleTask' or 'singleInstance'. "
                                    "Please see https://promon.co/strandhogg-2-0/ for more details",
                                    ["Strandhogg"])
        else:
            self.writer.startWriter("STRANDHOGG_2",
                                    LEVEL_INFO,
                                    "Standhogg 2.0",
                                    "This application does not seem to be vulnerable to the Standhogg 2.0 vulnerability",
                                    ["Strandhogg"])

    def analyze(self) -> None:
        self.check_strandhogg2()
