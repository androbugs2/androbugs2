from vector_base import VectorBase
from constants import *
from engines import *

class Vector(VectorBase):
    description = "SQLiteDatabase - beginTransactionNonExclusive() checking "

    def analyze(self) -> None:
        # pragma key
        found_strings = self.analysis.find_strings("PRAGMA\s*key\s*=")

        if found_strings:
            self.writer.startWriter("HACKER_DB_KEY", LEVEL_NOTICE, "Key for Android SQLite Databases Encryption",
                                   "Found using the symmetric key(PRAGMA key) to encrypt the SQLite databases. \nRelated code:",
                                   ["Database", "Hacker"])


            for found_string in found_strings:
                self.writer.write(found_string.get_value())
                self._print_xrefs(found_string)
        else:
            self.writer.startWriter("HACKER_DB_KEY", LEVEL_INFO, "Key for Android SQLite Databases Encryption",
                                                      "Did not find using the symmetric key(PRAGMA key) to encrypt the SQLite databases (It's still possible that it might use but we did not find out).",
                                                      ["Database", "Hacker"])
        # SQLiteDatabase - beginTransactionNonExclusive() checking:

        int_min_sdk = int(self.apk.get_min_sdk_version())
        if (int_min_sdk is not None) and (int_min_sdk < 11):
            path_sq_lite_database_begin_transaction_non_exclusive = self.analysis.find_methods(
                "Landroid/database/sqlite/SQLiteDatabase;", "beginTransactionNonExclusive", "()V")
            path_sq_lite_database_begin_transaction_non_exclusive = self.filtering_engine.filter_method_class_analysis_list(
                                                                                                    path_sq_lite_database_begin_transaction_non_exclusive)

            if path_sq_lite_database_begin_transaction_non_exclusive:
                output_string = """We detect you're using \"beginTransactionNonExclusive\" in your \"SQLiteDatabase\" but your minSdk supports down to %d.
                    \"beginTransactionNonExclusive\" is not supported by API < 11. Please make sure you use \"beginTransaction\" in the earlier version of Android.
                    Reference: http://developer.android.com/reference/android/database/sqlite/SQLiteDatabase.html#beginTransactionNonExclusive()")""" % int_min_sdk
                self.writer.startWriter("DB_DEPRECATED_USE1", LEVEL_CRITICAL,
                                   "SQLiteDatabase Transaction Deprecated Checking",
                                   output_string, ["Database"])

                self.writer.show_Paths(path_sq_lite_database_begin_transaction_non_exclusive)
            else:
                self.writer.startWriter("DB_DEPRECATED_USE1", LEVEL_INFO, "SQLiteDatabase Transaction Deprecated Checking",
                                   "Ignore checking \"SQLiteDatabase:beginTransactionNonExclusive\" you're not using it.",
                                   ["Database"])
        else:
            self.writer.startWriter("DB_DEPRECATED_USE1", LEVEL_INFO, "SQLiteDatabase Transaction Deprecated Checking",
                               "Ignore checking \"SQLiteDatabase:beginTransactionNonExclusive\" because your set minSdk >= 11.",
                               ["Database"])

        # Find "SQLite Encryption Extension (SEE) on Android"
        has_SSE_databases = False
        for cls in self.dalvik.get_classes():
            if cls.get_name() == "Lorg/sqlite/database/sqlite/SQLiteDatabase;":  # Don't do the exclusion checking on this one because it's not needed
                has_SSE_databases = True
                break

        if has_SSE_databases:
            self.writer.startWriter("DB_SEE", LEVEL_NOTICE,
                               "Android SQLite Databases Encryption (SQLite Encryption Extension (SEE))",
                               "This app is using SQLite Encryption Extension (SEE) on Android (http://www.sqlite.org/android) to encrypt or decrpyt databases.",
                               ["Database"])

        else:
            self.writer.startWriter("DB_SEE", LEVEL_INFO,
                               "Android SQLite Databases Encryption (SQLite Encryption Extension (SEE))",
                               "This app is \"NOT\" using SQLite Encryption Extension (SEE) on Android (http://www.sqlite.org/android) to encrypt or decrpyt databases.",
                               ["Database"])

        # Searching SQLite "PRAGMA key" encryption:

        result_sqlite_encryption = False
        strings_analysis = self.analysis.get_strings_analysis()
        for string, string_analysis in strings_analysis.items():
            if string == "$__sqlite_encryption__":
                result_sqlite_encryption = string_analysis
                break

        if result_sqlite_encryption:
            self.writer.startWriter("HACKER_DB_KEY", LEVEL_NOTICE, "Key for Android SQLite Databases Encryption",
                               "Found using the symmetric key(PRAGMA key) to encrypt the SQLite databases. \nRelated code:",
                               ["Database", "Hacker"])
            self._print_xrefs(result_sqlite_encryption)
        else:
            self.writer.startWriter("HACKER_DB_KEY", LEVEL_INFO, "Key for Android SQLite Databases Encryption",
                               "Did not find using the symmetric key(PRAGMA key) to encrypt the SQLite databases (It's still possible that it might use but we did not find out).",
                               ["Database", "Hacker"])

        # Checking whether the app is using SQLCipher:
        isUsingSQLCipher = False

        regexp_sqlcipher_database_class = re.compile(".*/SQLiteDatabase;")
        for method in self.dalvik.get_methods():
            # checks if method is native
            if 0x100 & method.get_access_flags():
                class_name = method.get_class_name()
                if regexp_sqlcipher_database_class.match(class_name):
                    if (method.get_name() == "dbopen") or (
                            method.get_name() == "dbclose"):  # Make it to 2 conditions to add efficiency
                        isUsingSQLCipher = True  # This is for later use

        if isUsingSQLCipher:
            self.writer.startWriter("DB_SQLCIPHER", LEVEL_NOTICE, "Android SQLite Databases Encryption (SQLCipher)",
                               "This app is using SQLCipher(http://sqlcipher.net/) to encrypt or decrpyt databases.",
                               ["Database"])

            path_sqlcipher_dbs = list(self.analysis.find_methods(descriptor="\(\)Linfo/guardianproject/database/sqlcipher/SQLiteDatabase;"))
            path_sqlcipher_dbs.append(list(self.analysis.find_methods(descriptor="\(\)Lnet/sqlcipher/database/SQLiteDatabase;")))
            path_sqlcipher_dbs = self.filtering_engine.filter_method_class_analysis_list(path_sqlcipher_dbs)

            if path_sqlcipher_dbs:
                # Get versions:
                has_version1or0 = False
                has_version2 = False
                for _, version in path_sqlcipher_dbs:
                    if version == 1:
                        has_version1or0 = True
                    if version == 2:
                        has_version2 = True

                if has_version1or0:
                    self.writer.write(
                        "It's using \"SQLCipher for Android\" (Library version: 1.X or 0.X), package name: \"info.guardianproject.database\"")
                if has_version2:
                    self.writer.write(
                        "It's using \"SQLCipher for Android\" (Library version: 2.X or higher), package name: \"net.sqlcipher.database\"")

                # Dumping:
                for db_path, version in path_sqlcipher_dbs:
                    self.writer.show_Path(db_path)

        else:
            self.writer.startWriter("DB_SQLCIPHER", LEVEL_INFO, "Android SQLite Databases Encryption (SQLCipher)",
                               "This app is \"NOT\" using SQLCipher(http://sqlcipher.net/) to encrypt or decrpyt databases.",
                               ["Database"])

        # SQLite databases
        is_using_android_dbs = self.analysis.find_methods(descriptor="\(\)Landroid/database/sqlite/SQLiteDatabase;")
        is_using_android_dbs = self.filtering_engine.filter_method_class_analysis_list(is_using_android_dbs)
        if is_using_android_dbs:
            if int_min_sdk < 15:
                self.writer.startWriter("DB_SQLITE_JOURNAL", LEVEL_NOTICE,
                                   "Android SQLite Databases Vulnerability Checking",
                                   """This app is using Android SQLite databases.
    Prior to Android 4.0, Android has SQLite Journal Information Disclosure Vulnerability.
    But it can only be solved by users upgrading to Android > 4.0 and YOU CANNOT SOLVE IT BY YOURSELF (But you can use encrypt your databases and Journals by "SQLCipher" or other libs).
    Proof-Of-Concept Reference:
    (1) http://blog.watchfire.com/files/androidsqlitejournal.pdf
    (2) http://www.youtube.com/watch?v=oCXLHjmH5rY """, ["Database"], "CVE-2011-3901")
            else:
                self.writer.startWriter("DB_SQLITE_JOURNAL", LEVEL_NOTICE,
                                   "Android SQLite Databases Vulnerability Checking",
                                   "This app is using Android SQLite databases but it's \"NOT\" suffering from SQLite Journal Information Disclosure Vulnerability.",
                                   ["Database"], "CVE-2011-3901")
        else:
            self.writer.startWriter("DB_SQLITE_JOURNAL", LEVEL_INFO, "Android SQLite Databases Vulnerability Checking",
                               "This app is \"NOT\" using Android SQLite databases.", ["Database"], "CVE-2011-3901")
