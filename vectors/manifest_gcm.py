import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks if sdk allows Google Cloud Messaging (Push Message) service"
    tags = ["MANIFEST_GCM"]

    def analyze(self) -> None:

        if self.int_min_sdk is not None and self.int_min_sdk < 8:  # Android 2.2=SDK 8

            output_string = """Your supporting minSdk is %d
        You are now allowing minSdk to less than 8. Please check: http://developer.android.com/about/dashboards/index.html
        Google Cloud Messaging (Push Message) service only allows Android SDK >= 8 (Android 2.2). Pleae check: http://developer.android.com/google/gcm/gcm.html
        You may have the change to use GCM in the future, so please set minSdk to at least 9.""" % self.int_min_sdk

            self.writer.startWriter("MANIFEST_GCM", LEVEL_NOTICE, "Google Cloud Messaging Suggestion", output_string)

        else:
            self.writer.startWriter("MANIFEST_GCM", LEVEL_INFO, "Google Cloud Messaging Suggestion", "Nothing to suggest.")
