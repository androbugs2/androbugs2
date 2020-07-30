import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "Checks SMS sending"
    tags = ["SENSITIVE_SMS"]
    def analyze(self) -> None:
        """
          Example:
            Landroid/telephony/SmsManager;->sendDataMessage(Ljava/lang/String; Ljava/lang/String; S [B Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V
            Landroid/telephony/SmsManager;->sendMultipartTextMessage(Ljava/lang/String; Ljava/lang/String; Ljava/util/ArrayList; Ljava/util/ArrayList; Ljava/util/ArrayList;)V
            Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V
        """

        path_sms_sending = list(self.analysis.find_methods("Landroid/telephony/SmsManager;", "sendDataMessage",
                                                           "\(Ljava/lang/String; Ljava/lang/String; S \[B Landroid/app/PendingIntent; Landroid/app/PendingIntent;\)V"))
        path_sms_sending.extend(self.analysis.find_methods("Landroid/telephony/SmsManager;", "sendMultipartTextMessage",
                                                           "\(Ljava/lang/String; Ljava/lang/String; Ljava/util/ArrayList; Ljava/util/ArrayList; Ljava/util/ArrayList;\)V"))
        path_sms_sending.extend(self.analysis.find_methods("Landroid/telephony/SmsManager;", "sendTextMessage",
                                                           "\(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;\)V"))
        path_sms_sending = staticDVM.get_paths(path_sms_sending)
        if path_sms_sending:
            self.writer.startWriter("SENSITIVE_SMS", LEVEL_WARNING, "Codes for Sending SMS",
                                    "This app has code for sending SMS messages (sendDataMessage, sendMultipartTextMessage or sendTextMessage):")
            self.writer.show_Paths(path_sms_sending)
        else:
            self.writer.startWriter("SENSITIVE_SMS", LEVEL_INFO, "Codes for Sending SMS",
                                    "Did not detect this app has code for sending SMS messages (sendDataMessage, sendMultipartTextMessage or sendTextMessage).")
