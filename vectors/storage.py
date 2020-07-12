import staticDVM
from vector_base import VectorBase
from constants import *


class Vector(VectorBase):
    description = "MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE checking"

    def analyze(self) -> None:
        """
               MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE checking:

               MODE_WORLD_READABLE = 1
               MODE_WORLD_WRITEABLE = 2
               MODE_WORLD_READABLE + MODE_WORLD_WRITEABLE = 3

               http://jimmy319.blogspot.tw/2011/07/android-internal-storagefile-io.html

               Example Java Code:
                   FileOutputStream outputStream = openFileOutput("Hello_World", Activity.MODE_WORLD_READABLE);

               Example Smali Code:
                   const-string v3, "Hello_World"
                   const/4 v4, 0x1
                   invoke-virtual {p0, v3, v4}, Lcom/example/android_mode_world_testing/MainActivity;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;
           """

        # Get a list of 'PathP' objects that are vulnerabilities
        list_path_openOrCreateDatabase = []
        list_path_openOrCreateDatabase2 = []
        list_path_getDir = []
        list_path_getSharedPreferences = []
        list_path_openFileOutput = []

        path_openOrCreateDatabase = self.analysis.find_methods(methodname="openOrCreateDatabase",
                                                               descriptor="(Ljava/landescriptor=g/String; I Landroid/database/sqlite/SQLiteDatabase$CursorFactory;)Landroid/database/sqlite/SQLiteDatabase;")
        path_openOrCreateDatabase = self.filtering_engine.filter_method_class_analysis_list(next(path_openOrCreateDatabase)) if any(path_openOrCreateDatabase) else []
        for i in staticDVM.trace_register_value_by_param_in_source_paths( path_openOrCreateDatabase):
            if (0x1 <= i.getResult()[2] <= 0x3):
                list_path_openOrCreateDatabase.append(i.getPath())

        path_openOrCreateDatabase2 = self.analysis.find_methods(methodname="openOrCreateDatabase",
                                                                descriptor="(Ljava/lang/String; I Landroid/database/sqlite/SQLiteDatabase$CursorFactory; Landroid/database/DatabaseErrorHandler;)Landroid/database/sqlite/SQLiteDatabase;")
        path_openOrCreateDatabase2 = self.filtering_engine.filter_method_class_analysis_list(next(path_openOrCreateDatabase2)) if any(path_openOrCreateDatabase2) else []
        for i in staticDVM.trace_register_value_by_param_in_source_paths( path_openOrCreateDatabase2):
            if (0x1 <= i.getResult()[2] <= 0x3):
                list_path_openOrCreateDatabase2.append(i.getPath())

        path_getDir = self.analysis.find_methods(methodname="getDir",
                                                 descriptor="(Ljava/lang/String; I)Ljava/io/File;")
        path_getDir =  self.filtering_engine.filter_method_class_analysis_list(next(path_getDir)) if any(path_getDir) else []
        for i in staticDVM.trace_register_value_by_param_in_source_paths( path_getDir):
            if (0x1 <= i.getResult()[2] <= 0x3):
                list_path_getDir.append(i.getPath())

        path_getSharedPreferences = self.analysis.find_methods(methodname="getSharedPreferences",
                                                               descriptor="(Ljava/lang/String; I)Landroid/content/SharedPreferences;")
        path_getSharedPreferences = self.filtering_engine.filter_method_class_analysis_list(next(path_getSharedPreferences)) if any(path_getSharedPreferences) else []
        for i in staticDVM.trace_register_value_by_param_in_source_paths( path_getSharedPreferences):
            if (0x1 <= i.getResult()[2] <= 0x3):
                list_path_getSharedPreferences.append(i.getPath())

        path_openFileOutput = self.analysis.find_methods(methodname="openFileOutput",
                                                         descriptor="(Ljava/lang/String; I)Ljava/io/FileOutputStream;")
        path_openFileOutput = self.filtering_engine.filter_method_class_analysis_list(next(path_openFileOutput)) if any(path_openFileOutput) else []
        for i in staticDVM.trace_register_value_by_param_in_source_paths( path_openFileOutput):
            if (0x1 <= i.getResult()[2] <= 0x3):
                list_path_openFileOutput.append(i.getPath())

        if list_path_openOrCreateDatabase or list_path_openOrCreateDatabase2 or list_path_getDir or list_path_getSharedPreferences or list_path_openFileOutput:

            self.writer.startWriter("MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE", LEVEL_CRITICAL,
                               "App Sandbox Permission Checking",
                               "Security issues \"MODE_WORLD_READABLE\" or \"MODE_WORLD_WRITEABLE\" found (Please check: https://www.owasp.org/index.php/Mobile_Top_10_2014-M2):")

            if list_path_openOrCreateDatabase:
                self.writer.write("[openOrCreateDatabase - 3 params]")
                for i in list_path_openOrCreateDatabase:
                    self.writer.show_Path(self.dalvik, i)
                self.writer.write("--------------------------------------------------")
            if list_path_openOrCreateDatabase2:
                self.writer.write("[openOrCreateDatabase - 4 params]")
                for i in list_path_openOrCreateDatabase2:
                    self.writer.show_Path(self.dalvik, i)
                self.writer.write("--------------------------------------------------")
            if list_path_getDir:
                self.writer.write("[getDir]")
                for i in list_path_getDir:
                    self.writer.show_Path(self.dalvik, i)
                self.writer.write("--------------------------------------------------")
            if list_path_getSharedPreferences:
                self.writer.write("[getSharedPreferences]")
                for i in list_path_getSharedPreferences:
                    self.writer.show_Path(self.dalvik, i)
                self.writer.write("--------------------------------------------------")
            if list_path_openFileOutput:
                self.writer.write("[openFileOutput]")
                for i in list_path_openFileOutput:
                    self.writer.show_Path(self.dalvik, i)
                self.writer.write("--------------------------------------------------")

        else:
            self.writer.startWriter("MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE", LEVEL_INFO,
                               "App Sandbox Permission Checking",
                               "No security issues \"MODE_WORLD_READABLE\" or \"MODE_WORLD_WRITEABLE\" found on 'openOrCreateDatabase' or 'openOrCreateDatabase2' or 'getDir' or 'getSharedPreferences' or 'openFileOutput'")

        # Get External Storage Directory access invoke

        paths_external_storage_access = self.analysis.find_methods(
            "Landroid/os/Environment;", "getExternalStorageDirectory", "()Ljava/io/File;")
        paths_external_storage_access = self.filtering_engine.filter_method_class_analysis_list(paths_external_storage_access)

        if paths_external_storage_access:
            self.writer.startWriter("EXTERNAL_STORAGE", LEVEL_WARNING, "External Storage Accessing",
                               "External storage access found (Remember DO NOT write important files to external storages):")
            self.writer.show_Paths(self.dalvik, paths_external_storage_access)
        else:
            self.writer.startWriter("EXTERNAL_STORAGE", LEVEL_INFO, "External Storage Accessing",
                               "External storage access not found.")

        # File delete alert

        path_FileDelete = self.analysis.find_methods("Ljava/io/File;", "delete")
        path_FileDelete = self.filtering_engine.filter_method_class_analysis_list(path_FileDelete)

        if path_FileDelete:
            self.writer.startWriter("FILE_DELETE", LEVEL_NOTICE, "File Unsafe Delete Checking",
                               """Everything you delete may be recovered by any user or attacker, especially rooted devices.
    Please make sure do not use "file.delete()" to delete essential files.
    Check this video: https://www.youtube.com/watch?v=tGw1fxUD-uY""")
            self.writer.show_Paths(self.dalvik, path_FileDelete)
        else:
            self.writer.startWriter("FILE_DELETE", LEVEL_INFO, "File Unsafe Delete Checking",
                               "Did not detect that you are unsafely deleting files.")