import hashlib
import traceback

from traitlets import Type

import vectors
from vector_base import VectorBase
from writer import *
import argparse
from datetime import datetime
import random
from zipfile import BadZipfile
import platform
from configparser import SafeConfigParser
import sys
import importlib
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from glob import glob
import os
import time

ANALYZE_MODE_SINGLE = "single"
ANALYZE_MODE_MASSIVE = "massive"
ANALYZE_ENGINE_BUILD_DEFAULT = 1  # Analyze Engine(use only number)

DIRECTORY_APK_FILES = ""  # "APKs/"

LINE_MAX_OUTPUT_CHARACTERS_WINDOWS = 160  # 100
LINE_MAX_OUTPUT_CHARACTERS_LINUX = 160
LINE_MAX_OUTPUT_INDENT = 20

"""
	*****************************************************************************
	** AndroBugs Framework - Android App Security Vulnerability Scanner        **
	** This tool was originally created by Yu-Cheng Lin                        **
	** Modifications by Jasper van Thuijl & Noam Drong                         **
	** Version: 2.0                                                            **
	*****************************************************************************

	** Read Python codeing style first: http://www.python.org/dev/peps/pep-0008/ **

	1.This script run under Python 2.7. DO NOT use Python 3.x

	2.You need to install 'chilkat' component version in accordance with Python 2.7 first. This is for certificate checking.
	  See the explanation of function 'def get_certificate(self, filename)' in 'apk.py' file
	  => It becomes optional now. Since the related code is not comment out for ease of use and install.

	3.Use command 'grep -nFr "#Added by AndroBugs" *' to see what AndroBugs Framework has added to Androguard Open Source project under "tools/modified/androguard" root directory.

	4.Notice the "encoding" when copy and paste into this file (For example: the difference between single quote ' ).

	5.** Notice: In AndroidManifest.xml => The value "TRUE" or "True" or "true" are all the same (e.g. [android:exported="TRUE"] equals to [android:exported="true"]). 
	  So if you want to check whether it is true, you should MAKE IT LOWER first. Otherwise, your code may have security issues. **

	Read these docs first:
		1.http://s.android.com/tech/dalvik/dex-format.html
		2.http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html

	Provide the user the options:
		1.Specify the excluded package name (ex: Facebook.com, Parse.com) and put it into "STR_REGEXP_TYPE_EXCLUDE_CLASSES"
		2.Show the "HTTP Connection" related code or not
		3.Show the "KeyStore" related code or not

	Flag:
		[Critical] => very critical
		[Warning]  => it's ok and not really need to change
		[Notice]   => For hackers, you should notice.
		[Info]	   => Information

	You can use these functions provided by the FilteringEngine to exclude class packages:
		(1)Filter single class name:
			is_class_name_not_in_exclusion(single_class_name_string)

		(2)Filter a list of class name:
			filter_list_of_classes(class_name_list)

		(3)Filter a list of method name:
			filter_list_of_methods(method_list)

		(4)Filter a list of Path:
			filter_list_of_paths(d, path_list)  #a list of PathP

		(5)Filter a list of Variables: #variables_list example: None or [[('R', 166), 5058]] or [[('R', 8), 5050], [('R', 24), 5046]]
			filter_list_of_variables(d, variables_list)   

		(6)Filter dictionary key classes: (filter the class names in the key)
			(boolean) is_all_of_key_class_in_dict_not_in_exclusion(key)

		(7) ...

	Current self-defined error id:
		 - fail_to_unzip_apk_file
		 - apk_file_name_slash_twodots_error
		 - apk_file_not_exist
		 - package_name_empty
		 - classes_dex_not_in_apk

		 search the corresponding error by using MongoDB criteria " {"analyze_error_id":"[error_id]"} "

	AndroBugs Framework is supported with MongoDB. Add "-s" argument if you want all the analysis results to be stored into the MongoDB.
	Please check the "androbugs-db.cfg" file for database configuration.

"""

def parseArgument():
    parser = argparse.ArgumentParser(description='AndroBugs Framework - Android App Security Vulnerability Scanner')
    parser.add_argument("-f", "--apk_file", help="APK File to analyze", type=str, required=True)
    parser.add_argument("-m", "--analyze_mode", help="Specify \"single\"(default) or \"massive\"", type=str,
                        required=False, default=ANALYZE_MODE_SINGLE)
    parser.add_argument("-b", "--analyze_engine_build", help="Analysis build number.", type=int, required=False,
                        default=ANALYZE_ENGINE_BUILD_DEFAULT)
    parser.add_argument("-t", "--analyze_tag", help="Analysis tag to uniquely distinguish this time of analysis.",
                        type=str, required=False, default=None)
    parser.add_argument("-e", "--extra",
                        help="1)Do not check(default)  2)Check  security class names, method names and native methods",
                        type=int, required=False, default=1)
    parser.add_argument("-c", "--line_max_output_characters",
                        help="Setup the maximum characters of analysis output in a line", type=int, required=False)
    parser.add_argument("-s", "--store_analysis_result_in_db",
                        help="Specify this argument if you want to store the analysis result in MongoDB. Please add this argument if you have MongoDB connection.",
                        action="store_true")
    parser.add_argument("-v", "--show_vector_id",
                        help="Specify this argument if you want to see the Vector ID for each vector.",
                        action="store_true")

    # When you want to use "report_output_dir", remember to use "os.path.join(args.report_output_dir, [filename])"
    parser.add_argument("-o", "--report_output_dir", help="Analysis Report Output Directory", type=str, required=False,
                        default=DIRECTORY_REPORT_OUTPUT)

    args = parser.parse_args()
    return args

def isNullOrEmptyString(input_string, strip_whitespaces=False):
    if input_string is None:
        return True
    if strip_whitespaces:
        if input_string.strip() == "":
            return True
    else:
        if input_string == "":
            return True
    return False

def get_hash_scanning(writer):
    # signature = hash(package_name(default="") + "-" + file_sha256(default="") + "-" + timestamp_long + "-" + random_number_length8)
    # use "-" because aaa-bbb.com is not a valid domain name
    tmp_original = writer.getInf("package_name", "pkg") + "-" + writer.getInf("file_sha256", "sha256") + "-" + str(
        time.time()) + "-" + str(random.randrange(10000000, 99999999))
    tmp_hash = hashlib.sha512(tmp_original.encode()).hexdigest()
    return tmp_hash

def get_hash_exception(writer):
    # signature = hash(analyze_error_id(default="") + "-" + file_sha256(default="") + "-" + timestamp_long + "-" + random_number_length8)
    tmp_original = writer.getInf("analyze_error_id", "err") + "-" + writer.getInf("file_sha256", "sha256") + "-" + str(
        time.time()) + "-" + str(random.randrange(10000000, 99999999))
    tmp_hash = hashlib.sha512(tmp_original.encode()).hexdigest()
    return tmp_hash

def get_hashes_by_filename(filename):
    md5 = None
    sha1 = None
    sha256 = None
    sha512 = None
    with open(filename, 'r', encoding='ISO-8859-1') as f:
        data = f.read().encode()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()
    return md5, sha1, sha256, sha512

class ExpectedException(Exception):
    def __init__(self, err_id, message):
        self.err_id = err_id
        self.message = message

    def __str__(self):
        return "[" + self.err_id + "] " + self.message

    def get_err_id(self):
        return self.err_id

    def get_err_message(self):
        return self.message

def __persist_db(writer, args):
    # starting_dvm
    # starting_androbugs

    if platform.system().lower() == "windows":
        db_config_file = os.path.join(os.path.dirname(sys.executable), 'androbugs-db.cfg')
    else:
        db_config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'androbugs-db.cfg')

    if not os.path.isfile(db_config_file):
        print(("[ERROR] AndroBugs Framework DB config file not found: " + db_config_file))
        traceback.print_exc()

    configParser = SafeConfigParser()
    configParser.read(db_config_file)

    MongoDB_Hostname = configParser.get('DB_Config', 'MongoDB_Hostname')
    MongoDB_Port = configParser.getint('DB_Config', 'MongoDB_Port')
    MongoDB_Database = configParser.get('DB_Config', 'MongoDB_Database')

    Collection_Analyze_Result = configParser.get('DB_Collections', 'Collection_Analyze_Result')
    Collection_Analyze_Success_Results = configParser.get('DB_Collections', 'Collection_Analyze_Success_Results')
    Collection_Analyze_Success_Results_FastSearch = configParser.get('DB_Collections',
                                                                     'Collection_Analyze_Success_Results_FastSearch')
    Collection_Analyze_Fail_Results = configParser.get('DB_Collections', 'Collection_Analyze_Fail_Results')

    from pymongo import MongoClient
    client = MongoClient(MongoDB_Hostname, MongoDB_Port)
    db = client[MongoDB_Database]  # Name is case-sensitive

    analyze_status = writer.get_analyze_status()

    try:

        if analyze_status is not None:
            # You might not get Package name when in "starting_apk" stage

            packed_analyzed_results = writer.get_packed_analyzed_results_for_mongodb()  # "details" will only be shown when success
            packed_analyzed_results_fast_search = writer.get_search_enhanced_packed_analyzed_results_for_mongodb()  # specifically designed for Massive Analysis

            collection_AppInfo = db[Collection_Analyze_Result]  # Name is case-sensitive
            collection_AppInfo.insert(packed_analyzed_results)

            if analyze_status == "success":  # save analyze result only when successful
                collection_AnalyzeSuccessResults = db[Collection_Analyze_Success_Results]
                collection_AnalyzeSuccessResults.insert(packed_analyzed_results)

                collection_AnalyzeSuccessResultsFastSearch = db[Collection_Analyze_Success_Results_FastSearch]
                collection_AnalyzeSuccessResultsFastSearch.insert(packed_analyzed_results_fast_search)

        if (analyze_status == "fail"):
            collection_AnalyzeExceptions = db[Collection_Analyze_Fail_Results]  # Name is case-sensitive
            collection_AnalyzeExceptions.insert(writer.getInf())

    # pymongo.errors.BulkWriteError, pymongo.errors.CollectionInvalid, pymongo.errors.CursorNotFound, pymongo.errors.DocumentTooLarge, pymongo.errors.DuplicateKeyError, pymongo.errors.InvalidOperation
    except Exception as err:
        try:
            writer.update_analyze_status("fail")
            writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

            writer.writeInf_ForceNoPrint("analyze_error_type_expected", False)
            writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
            writer.writeInf_ForceNoPrint("analyze_error_id", str(type(err)))
            writer.writeInf_ForceNoPrint("analyze_error_message", str(err))

            packed_analyzed_results = writer.getInf()
            """
				http://stackoverflow.com/questions/5713218/best-method-to-delete-an-item-from-a-dict
				There's also the minor point that .pop will be slightly slower than the del since it'll translate to a function call rather than a primitive.
				packed_analyzed_results.pop("details", None)	#remove the "details" tag, if the key is not found => return "None"
			"""
            if "details" in packed_analyzed_results:  # remove "details" result to prevent the issue is generating by the this item
                del packed_analyzed_results["details"]

            collection_AnalyzeExceptions = db[Collection_Analyze_Fail_Results]  # Name is case-sensitive
            collection_AnalyzeExceptions.insert(packed_analyzed_results)
        except:
            if DEBUG:
                print("[Error on writing Exception to MongoDB]")
                traceback.print_exc()

def __persist_file(writer, args):
    package_name = writer.getInf("package_name")
    signature_unique_analyze = writer.getInf("signature_unique_analyze")

    if package_name and signature_unique_analyze:
        return writer.save_result_to_file(
            os.path.join(args.report_output_dir, package_name + "_" + signature_unique_analyze + ".txt"), args)
    else:
        print("\"package_name\" or \"signature_unique_analyze\" not exist.")
        return False

def __analyze(writer, args):
    """
		Exception:
			apk_file_not_exist
			classes_dex_not_in_apk
	"""

    # StopWatch: Counting execution time...
    start_time = datetime.now()

    # efficientStringSearchEngine = EfficientStringSearchEngine()
    # filteringEngine = FilteringEngine(ENABLE_EXCLUDE_CLASSES, STR_REGEXP_TYPE_EXCLUDE_CLASSES)

    isUsingSQLCipher = False
    isMasterKeyVulnerability = False

    if args.line_max_output_characters is None:
        if platform.system().lower() == "windows":
            args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_WINDOWS - LINE_MAX_OUTPUT_INDENT
        else:
            args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_LINUX - LINE_MAX_OUTPUT_INDENT

    if not os.path.isdir(args.report_output_dir):
        os.mkdir(args.report_output_dir)

    writer.writeInf_ForceNoPrint("analyze_mode", args.analyze_mode)
    writer.writeInf_ForceNoPrint("analyze_engine_build", args.analyze_engine_build)
    if args.analyze_tag:
        writer.writeInf_ForceNoPrint("analyze_tag", args.analyze_tag)

    APK_FILE_NAME_STRING = DIRECTORY_APK_FILES + args.apk_file
    apk_Path = APK_FILE_NAME_STRING  # + ".apk"

    if (".." in args.apk_file):
        raise ExpectedException("apk_file_name_slash_twodots_error",
                                "APK file name should not contain slash(/) or two dots(..) (File: " + apk_Path + ").")

    if not os.path.isfile(apk_Path):
        raise ExpectedException("apk_file_not_exist", "APK file not exist (File: " + apk_Path + ").")

    if args.store_analysis_result_in_db:
        try:
            importlib.util.find_spec('pymongo')
            found_pymongo_lib = True
        except ImportError:
            found_pymongo_lib = False

        if not found_pymongo_lib:
            pass

        # Cause some unexpected behavior on Linux => Temporarily comment it out
        # raise ExpectedException("libs_not_found_pymongo", "Python library \"pymongo\" is not found. Please install the library first: http://api.mongodb.org/python/current/installation.html.")

    # apk_filepath_relative = apk_Path
    apk_filepath_absolute = os.path.abspath(apk_Path)

    # writer.writeInf_ForceNoPrint("apk_filepath_relative", apk_filepath_relative)
    writer.writeInf_ForceNoPrint("apk_filepath_absolute", apk_filepath_absolute)

    apk_file_size = float(os.path.getsize(apk_filepath_absolute)) / (1024 * 1024)
    writer.writeInf_ForceNoPrint("apk_file_size", apk_file_size)

    writer.update_analyze_status("loading_apk")

    writer.writeInf_ForceNoPrint("time_starting_analyze", datetime.utcnow())

    a = apk.APK(apk_Path)

    writer.update_analyze_status("starting_apk")

    package_name = a.get_package()

    if isNullOrEmptyString(package_name, True):
        raise ExpectedException("package_name_empty", "Package name is empty (File: " + apk_Path + ").")

    writer.writeInf("platform", "Android", "Platform")
    writer.writeInf("package_name", str(package_name), "Package Name")

    # Check: http://developer.android.com/guide/topics/manifest/manifest-element.html
    if not isNullOrEmptyString(a.get_androidversion_name()):
        try:
            writer.writeInf("package_version_name", str(a.get_androidversion_name()), "Package Version Name")
        except:
            writer.writeInf("package_version_name", a.get_androidversion_name().encode('ascii', 'ignore'),
                            "Package Version Name")

    if not isNullOrEmptyString(a.get_androidversion_code()):
        # The version number shown to users. This attribute can be set as a raw string or as a reference to a string resource.
        # The string has no other purpose than to be displayed to users.
        try:
            writer.writeInf("package_version_code", int(a.get_androidversion_code()), "Package Version Code")
        except ValueError:
            writer.writeInf("package_version_code", a.get_androidversion_code(), "Package Version Code")

    if len(a.get_dex()) == 0:
        raise ExpectedException("classes_dex_not_in_apk",
                                "Broken APK file. \"classes.dex\" file not found (File: " + apk_Path + ").")

    try:
        str_min_sdk_version = a.get_min_sdk_version()
        if (str_min_sdk_version is None) or (str_min_sdk_version == ""):
            raise ValueError
        else:
            int_min_sdk = int(str_min_sdk_version)
            writer.writeInf("minSdk", int_min_sdk, "Min Sdk")
    except ValueError:
        # Check: http://developer.android.com/guide/topics/manifest/uses-sdk-element.html
        # If "minSdk" is not set, the default value is "1"
        writer.writeInf("minSdk", 1, "Min Sdk")
        int_min_sdk = 1

    try:
        str_target_sdk_version = a.get_target_sdk_version()
        if (str_target_sdk_version is None) or (str_target_sdk_version == ""):
            raise ValueError
        else:
            int_target_sdk = int(str_target_sdk_version)
            writer.writeInf("targetSdk", int_target_sdk, "Target Sdk")
    except ValueError:
        # Check: http://developer.android.com/guide/topics/manifest/uses-sdk-element.html
        # If not set, the default value equals that given to minSdkVersion.
        int_target_sdk = int_min_sdk

    md5, sha1, sha256, sha512 = get_hashes_by_filename(APK_FILE_NAME_STRING)
    writer.writeInf("file_md5", md5, "MD5   ")
    writer.writeInf("file_sha1", sha1, "SHA1  ")
    writer.writeInf("file_sha256", sha256, "SHA256")
    writer.writeInf("file_sha512", sha512, "SHA512")

    writer.update_analyze_status("starting_dvm")

    d = dvm.DalvikVMFormat(a.get_dex())

    writer.update_analyze_status("starting_analysis")

    dx = analysis.Analysis(d)

    writer.update_analyze_status("starting_androbugs")

    analysis_start = datetime.now()

    writer.update_analyze_status("loading_vectors")

    loaded_vector_classes = list()

    print("Loaded vectors:")
    file_list = os.listdir(os.path.dirname(vectors.__file__))
    for file_name in file_list:
        if file_name.endswith('.py') and file_name != '__init__.py':
            loaded_vector_classes.append(importlib.import_module('vectors.' + file_name.replace('.py', '')))
            print(file_name.replace('.py', ''))


    writer.update_analyze_status("checking_vectors")
    for vector_class in loaded_vector_classes:
        print("Running " + vector_class.__name__ + " analysis.")
        vector_class.Vector(writer, a, d, dx, args).analyze()

    # End of Checking

    # Must complete the last writer
    writer.completeWriter()
    writer.writeInf_ForceNoPrint("vector_total_count", writer.get_total_vector_count())


    # timing
    stop_time = datetime.now()
    total_elapsed_time = stop_time - start_time
    analysis_time = stop_time - analysis_start
    vm_loading_time = analysis_start - start_time

    writer.writeInf_ForceNoPrint("time_total", total_elapsed_time.total_seconds())
    writer.writeInf_ForceNoPrint("time_analyze", analysis_time.total_seconds())
    writer.writeInf_ForceNoPrint("time_loading_vm", vm_loading_time.total_seconds())

    writer.update_analyze_status("success")
    writer.writeInf_ForceNoPrint("time_finish_analyze", datetime.utcnow())

def main():
    args = parseArgument()

    writer = Writer()

    try:
        # Print Title
        writer.writePlainInf("""*************************************************************************
**   AndroBugs Framework - Android App Security Vulnerability Scanner  **
**                            version: 1.0.0                           **
**     author: Yu-Cheng Lin (@AndroBugs, http://www.AndroBugs.com)     **
**               contact: androbugs.framework@gmail.com                **
*************************************************************************""")

        # Analyze
        __analyze(writer, args)

        analyze_signature = get_hash_scanning(writer)
        writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                     analyze_signature)  # For uniquely distinguish the analysis report
        writer.append_to_file_io_information_output_list("Analyze Signature: " + analyze_signature)
        writer.append_to_file_io_information_output_list(
            "------------------------------------------------------------------------------------------------")

    except ExpectedException as err_expected:

        writer.update_analyze_status("fail")

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
        writer.writeInf_ForceNoPrint("analyze_error_id", err_expected.get_err_id())
        writer.writeInf_ForceNoPrint("analyze_error_message", err_expected.get_err_message())

        writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                     get_hash_scanning(writer))  # For uniquely distinguish the analysis report
        writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(writer))

        if DEBUG:
            print(err_expected)

    except BadZipfile as zip_err:  # This may happen in the "a = apk.APK(apk_Path)"

        writer.update_analyze_status("fail")

        # Save the fail message to db
        writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
        writer.writeInf_ForceNoPrint("analyze_error_id", "fail_to_unzip_apk_file")
        writer.writeInf_ForceNoPrint("analyze_error_message", str(zip_err))

        writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                     get_hash_scanning(writer))  # For uniquely distinguish the analysis report
        writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(writer))

        if DEBUG:
            print("[Unzip Error]")
            traceback.print_exc()

    except Exception as err:

        writer.update_analyze_status("fail")

        # Save the fail message to db
        writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", False)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
        writer.writeInf_ForceNoPrint("analyze_error_id", str(type(err)))
        writer.writeInf_ForceNoPrint("analyze_error_message", str(err))

        writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                     get_hash_scanning(writer))  # For uniquely distinguish the analysis report
        writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(writer))

        if DEBUG:
            traceback.print_exc()

    # Save to the DB
    if args.store_analysis_result_in_db:
        __persist_db(writer, args)

    if writer.get_analyze_status() == "success":

        if REPORT_OUTPUT == "print":
            writer.show(args)
        elif REPORT_OUTPUT == "file":
            __persist_file(writer, args)  # write report to "disk"
        elif REPORT_OUTPUT == "print_and_file":
            writer.show(args)
            __persist_file(writer, args)  # write report to "disk"

if __name__ == "__main__":
    main()
