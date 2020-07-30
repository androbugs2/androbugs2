import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks if Android getting sensitive information such as IMEI, Android_ID, UUID"
    tags = ["SENSITIVE_DEVICE_ID", "SENSITIVE_SECURE_ANDROID_ID"]

    def analyze(self) -> None:

        # Android getting IMEI, Android_ID, UUID problem

        path_Device_id = self.analysis.find_methods("Landroid/telephony/TelephonyManager;",
                                                    "getDeviceId", "\(\)Ljava/lang/String;")
        path_Device_id = staticDVM.get_paths(path_Device_id)

        if path_Device_id:

            self.writer.startWriter("SENSITIVE_DEVICE_ID", LEVEL_WARNING, "Getting IMEI and Device ID",
                                    """This app has code getting the "device id(IMEI)" but there are problems with this "TelephonyManager.getDeviceId()" approach.
    1.Non-phones: Wifi-only devices or music players that don't have telephony hardware just don't have this kind of unique identifier.
    2.Persistence: On devices which do have this, it persists across device data wipes and factory resets. It's not clear at all if, in this situation, your app should regard this as the same device.
    3.Privilege:It requires READ_PHONE_STATE permission, which is irritating if you don't otherwise use or need telephony.
    4.Bugs: We have seen a few instances of production phones for which the implementation is buggy and returns garbage, for example zeros or asterisks.
    If you want to get an unique id for the device, we suggest you use "Installation" framework in the following article.
    Please check the reference: http://android-developers.blogspot.tw/2011/03/identifying-app-installations.html
    """, ["Sensitive_Information"])

            self.writer.show_Paths(path_Device_id)

        else:

            self.writer.startWriter("SENSITIVE_DEVICE_ID", LEVEL_INFO, "Getting IMEI and Device ID",
                                    "Did not detect this app is getting the \"device id(IMEI)\" by \"TelephonyManager.getDeviceId()\" approach.",
                                    ["Sensitive_Information"])

        # Android "android_id"

        path_android_id = self.analysis.find_methods("Landroid/provider/Settings\$Secure;",
                                                     "getString",
                                                     "\(Landroid/content/ContentResolver; Ljava/lang/String;\)Ljava/lang/String;")

        list_android_id = []
        for i in staticDVM.trace_register_value_by_param_in_method_class_analysis_list(path_android_id):
            if i.getResult()[1] is None:
                continue
            if i.getResult()[1] == "android_id":
                list_android_id.append(i.getPath())

        if list_android_id:
            self.writer.startWriter("SENSITIVE_SECURE_ANDROID_ID", LEVEL_WARNING, "Getting ANDROID_ID",
                                    """This app has code getting the 64-bit number "Settings.Secure.ANDROID_ID". 
         ANDROID_ID seems a good choice for a unique device identifier. There are downsides: First, it is not 100% reliable on releases of Android prior to 2.2 (Froyo). 
         Also, there has been at least one widely-observed bug in a popular handset from a major manufacturer, where every instance has the same ANDROID_ID. 
         If you want to get an unique id for the device, we suggest you use "Installation" framework in the following article. 
         Please check the reference: http://android-developers.blogspot.tw/2011/03/identifying-app-installations.html 
         """, ["Sensitive_Information"])

            self.writer.show_Paths(list_android_id)
        else:

            self.writer.startWriter("SENSITIVE_SECURE_ANDROID_ID", LEVEL_INFO, "Getting ANDROID_ID",
                                    "Did not detect this app is getting the 64-bit number \"Settings.Secure.ANDROID_ID\".",
                                    ["Sensitive_Information"])