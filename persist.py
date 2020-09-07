import os
import platform
from configparser import ConfigParser
import sys
import traceback
from datetime import datetime
import constants


def __persist_db(writer, args):

    db_config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'androbugs-db.cfg')

    if not os.path.isfile(db_config_file):
        print(("[ERROR] AndroBugs Framework DB config file not found: " + db_config_file))
        traceback.print_exc()

    configParser = ConfigParser()
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

        if analyze_status == "fail":
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
            if constants.DEBUG:
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
