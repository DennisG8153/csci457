# FeatureExtractor.py
# Some feature extraction functions, meant to be used with ExtractWithProgress.py
# Run Directly to extract from a single file to a test directory
# Extracts features from an apk 
# Writes features to a file
# Updates a unique features file
# Reload features from a file into the unique_features dictionary

import os
import time
from datetime import datetime
from androguard.misc import AnalyzeAPK # APK analysis
#from androguard.core.apk import APK # Simpler but faster analysis, doesn't give us everything
from typing import Dict, List # dict to retain insertion order
# from collections import defaultdict # TODO: may use default dict

'''
#------------------------------------------------------------------------------------------------------------
#---------- MANY OF THESE FEATURES NEED MORE POST PROCESSING BECAUSE OF HIGH SPARCITY/CARDINALITY OF THE DATA
#---------- NEED TO TRAIN OUR FIRST MODEL BEFORE WE CONSIDER IMPROVING THE DATASET
#------------------------------------------------------------------------------------------------------------
# ORDER OF FEATURES BASED ON AMOUNT OF POST PROCESSING NEEDED/HOW USEFUL IN CURRENT STATE
#
# PERMISSIONS:  
#               likely no cardinality issue
#               easy to extract
#               good size dataset
#
# USED HARDWARE/SOFTWARE (aka USED FEATURES): 
#               used hardware and software
#               easy to extract
#               small dataset
#
# USED INTENTS: 
#               POTENTIAL CARDINALITY ISSUE,
#               but dataset won't be too large 
#               tokenization to improve
#
# API CALLS   
#               POTENTIAL CARDINALITY ISSUE
#               LARGE DATA SET
#               tokenization to improve
#
# EXTERNAL LIBRARIES:
#               POTENTIALLY MASSIVE DATA SET, 
#               HIGH CARDINALITY PROBABLE, 
#               BETTER TO TARGET OBFUSCATION WITH TOKENIZATION, 
#               DESPERATELY NEED TOKENIZATION TO BE USEFUL
#
# URLS: 
#               MASSIVE CARDINALITY, 
#               ESSENTIALLY USELESS WITHOUT TOKENIZATION
'''

# Type of feature to be extracted
# TODO consider switching to an enum class, need to import enum for that
FEATURE_TYPES = ["permissions", "used_hsware", "intents", "api_calls", "libraries", "urls"]

# NOTE: Directory Path to test extracting a single file, change to extract from a different file
#DEFAULT_TEST_APK_PATH = r"..\Datasets\Malicious\amd_data\DroidKungFu\variety2\0c3df9c1d759a53eb16024b931a3213a.apk"
#DEFAULT_TEST_APK_PATH = r"..\Datasets\Malicious\amd_data\DroidKungFu\variety2\01c3cc236c3587d20584ed84751c655c.apk"
DEFAULT_TEST_APK_PATH = r"..\Datasets\Malicious\amd_data\Finspy\variety1\4eea2753d42fef7dc74ea1c8350c659e.apk"
DEFAULT_TEST_OUTPUT_DIR_FEATURES = r"..\test_extracted_features\malicious_features"
DEFAULT_TEST_OUTPUT_DIR_UNIQUE = r"..\test_extracted_features\unique_features"

# Dictionary to store all unique features found across every apk
# Retains insertion order
# TODO: May switch to bool to count
# Capturing features seperately to put in separate files
unique_features: Dict[str, Dict[str, bool]] = {FEATURE_TYPES[0] : {}, # permissions
                                               FEATURE_TYPES[1] : {}, # used_hsware
                                               FEATURE_TYPES[2] : {}, # intents
                                               FEATURE_TYPES[3] : {}, # api_calls
                                               FEATURE_TYPES[4] : {}, # libraries
                                               FEATURE_TYPES[5] : {}} # urls

def extract_features(apk_path: str) -> Dict[str, Dict[str, bool]]: # TODO: consider changing to a dict[dict[]] to prevent issues with duplicates
    """
    Extracts features from an apk file and returns them as a List 

    Extracted Features:
        API Calls - Calls to external APIs
        Permissions - Permission requests to parts of device data
        Used Features - Requests for usage to device Hardware and Software functionality
        Used Intents - Accesses to intents sent/recieved by the application to/from the system, or other applications
        External Libraries - Use of external libraries within the application
        URL - URLS visited by the application, Not currently useful because of it's high cardinality, can post process

    Args:
        apk_path (str): The path to the APK file.
        
    Returns:
        Dict[str, List[str]]: A dictionary of each feature type and a list of extracted features of that type from the APK.
    """

    # Extract Features
    extracted_features: Dict[str, Dict[str, bool]] = {FEATURE_TYPES[0] : {}, # permissions
                                                    FEATURE_TYPES[1] : {}, # used_hsware
                                                    FEATURE_TYPES[2] : {}, # intents
                                                    FEATURE_TYPES[3] : {}, # apis
                                                    FEATURE_TYPES[4] : {}, # libraries
                                                    FEATURE_TYPES[5] : {}} # urls 

    try:
        # Load the APK file using androguard's APK class
        #a = APK(apk_path) # Less compute intensive, but less data available
        a, d, dx = AnalyzeAPK(apk_path) 
        
        # ---Extract Features---

        # Permissions and used hardware/software are easy
        # NOTE: No need to use Dict[] because extracted features handles duplicates
        permissions = a.get_permissions()
        hardware_software = a.get_features()

        # Intents need to be extracted from the string lists made by a.get_activities(), a.get_services() and a.get_recievers()
        # a.get_intent_filters(itemtype, item) gets a dictionary of components for each item in each List
        # itemtypes: activity, service, reciever 
        # each component then has 3 main intent types (i.e. action, category, data)
        # TODO: Make another enum for itemtypes for best coding practice
        activities = a.get_activities()
        services = a.get_services()
        recievers = a.get_receivers()
        intents = [] # NOTE: Using a List, overlaps will be removed by the extracted_features Dict
        for activity in activities: 
            act = a.get_intent_filters("activity", activity)
            for categories in act:
                for intent in act[categories]:
                    if type(intent) == str: # NOTE: No need to check for empty strings, checked when adding to extracted_features
                        intents.append(intent)
        for service in services: 
            serv = a.get_intent_filters("service", service)
            for categories in serv:
                for intent in serv[categories]:
                    if type(intent) == str: # NOTE: Needed to check the intent was a string and not another list data type (because that did happen once)
                        intents.append(intent)
        for reciever in recievers: 
            rec = a.get_intent_filters("reciever", reciever)
            for categories in rec:
                for intent in rec[categories]:
                    if type(intent) == str:
                        intents.append(intent)
    
        # Classes (APIs and External Libraries) are extracted with the dx.get_methods() and the method.get_xref_to() commands
        # Checking method calls is the most effective way to assure all imported classes are found
        # APIs start with android or java typically, everything else is considered an external library
        apis = []
        libraries = []
        methods = dx.get_methods()
        for method in methods:
            for _, call, _ in method.get_xref_to():
                classname = call.class_name[1:-1].replace("/", ".")   # Remove leading 'L' and trailing ';' Replace '/' with '.'
                methodname = call.name
                fullname = classname + "." + methodname
                if fullname.startswith("android") or fullname.startswith("java"):
                    apis.append(fullname)
                else:
                    libraries.append(fullname)

        # URLS are in the d object, which is an array of strings(?)
        # TODO: There is a lot of cleaning to be done on these strings 
        # and because we need tokenization to make them useful we will extract the raw strings 
        # and maybe we will post process them later
        # from how the raw dex data looked, most of the text was useless, 
        # needed to use regex to extract it properly, this might not be every relevant thing
        # there are sometimes http:// strings that are not followed by anything
        # Lots TODO TODO TODO
        urls = []
        for dex in d:
            for string in dex.get_strings():
                string = string.strip()
                if string.startswith("https://") or string.startswith("http://"):
                    urls.append(string.strip())

        # Put features in extracted_features with labels (labels are helpful)
        for p in permissions:
            if len(p): # Check for empty strings
                extracted_features[FEATURE_TYPES[0]][f"Permission: {p}"] = True
        for hs in hardware_software:
            if len(hs):
                extracted_features[FEATURE_TYPES[1]][f"Used Hardware/Software: {hs}"] = True
        # intents is a List[str], no longer a dictionary
        for intent in intents:
            if len(intent):
                extracted_features[FEATURE_TYPES[2]][f"Intent: {intent}"] = True
        # apis
        for api in apis:
            if len(api):
                extracted_features[FEATURE_TYPES[3]][f"API: {api}"] = True
        # libraries or class calls, need to settle on a name
        for library in libraries:
            if len(library):
                extracted_features[FEATURE_TYPES[4]][f"Library: {library}"] = True
        # urls
        for url in urls:
            if len(url):
                extracted_features[FEATURE_TYPES[5]][f"URL: {url}"] = True

    except FileNotFoundError:
        print(f"Error: APK file not found at path: {apk_path}")
        return []
    except Exception as e:
        print(f"Error processing APK {apk_path}: {e}")
        return []
    
    return extracted_features
    
def write_features(extracted_features: Dict[str, Dict[str, bool]], apk_path: str, output_dir: str):
    """
    Writes a list of features to a file that shares a name with the apk with '.txt' appended.
    
    Args:
        extracted_features (List[str]): The path to the APK file.
        apk_path (str): The path to the referenced directory. Created file uses the apk's name.
        output_dir (str): The directory where the output folders will be created.
    """

    # Check if directory exists, if not make it
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    # Creating the file path to write to, for individual apks all features are written in the same file    
    output_filepath = os.path.join(output_dir, f"{os.path.basename(apk_path)}.txt")

    # Write Features to File
    try:
        with open(output_filepath, 'w') as f:
            for feature_type in extracted_features: # feature types come after file opening because they are all written to the same file
                for feature in extracted_features[feature_type]:
                    if feature != "": # extra safety against empty strings
                        f.write(f"{feature}\n")
    except Exception as e:
        print(f"Error writing features for {apk_path}: {e}")

    #quick fix to track which files have been processed
    try:
        upper, _ = os.path.split(output_dir)
        log_path = os.path.join(upper, "apk_log.txt")
        with open(log_path, "a") as f:
            f.write(f"{os.path.basename(apk_path)}\n")
    except Exception as e:
        print(f"Error writing to log {apk_path}: {e}")
            


def update_unique_features(features: Dict[str, List[str]], output_dir: str):
    """
    Aggregates new features into the global UNIQUE_FEATURES dictionary and 
    writes the complete list of unique features to 'unique_features.txt'.
    Relies on reload_unique_features to not overwrite existing file
    
    Args:
        features (List[str]): A list of features extracted from a single APK.
        base_output_path (str): The root directory where the output folders should be created.
    """
    global unique_features
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    # Set output file path
    # output_filepath = os.path.join(output_dir, UNIQUE_FEATURES_FILENAMES) switching to multiple files, need multiple paths, achieved with loop

    try:
        for feature_type in features: # traverse 
            file_name = "unique_" + feature_type + ".txt" # Makes the file name for each feature
            with open(os.path.join(output_dir, file_name), 'a') as f:
                for feature in features[feature_type]:
                    if feature not in unique_features[feature_type]: # if statement prevents features from being written multiple times
                        (unique_features[feature_type])[feature] = True # add feature to feature_type that it belongs to, in the dictionary of feature types
                        f.write(f"{feature}\n") # append the appropriate feature to the file
    except Exception as e:
        print(f"Error appending to unique features file: {e}")

def reload_unique_features(output_dir: str):
    """
        Reloads unique features from text files into the correct UNIQUE_FEATURES dictionary.   
        Looks for subfolder and files: "\\unique_features" 
            "unique_permissions.txt", 
            "unique_hsware.txt", 
            "unique_intents.txt", 
            "unique_api_calls.txt", 
            "unique_libraries.txt", 
            "unique_urls.txt"
        
        Args:
            output_dir (str): Location where to find the existing unique_*.txt files exist
    """
    global unique_features #NOTE: this remains initialized when another class calls it

    for feature_type in FEATURE_TYPES: 
        file_name = "unique_" + feature_type + ".txt" # Make file name
        file_path = os.path.join(output_dir, file_name) # Join Path and file name
        if os.path.exists(file_path) and os.path.getsize(file_path): # Check if the file is there and that it's not empty
            try:
                with open(file_path, 'r') as f: # try opening
                    for line in f: 
                        if line.strip: # Ignore Empty Lines (just to be safe) TODO: Check if there are issues or problems within the unique features file, Throw Error or correct them
                            (unique_features[feature_type])[line.strip()] = True # add empty lines to dictionary of correct type
            except Exception as e:
                print(f"Error reading unique_features: {e}")
        else:
            print(f'INFO: {file_name} has not been created yet or was empty\n')

# TODO: This isn't in perfect working order right now, not gonna use it for now
def reload_processed_apks(output_dir: str) -> Dict[str, bool]:
    """
        Reloads unique apk files that were previously processed from a log file into the PREVIOUSLY_PROCESSED_APKS dictionary
        looks for apk_log.txt
        
        Args:
            output_dir (str): Location where to find the apk_log.txt file
        Returns:
            A dictionary of all apk file names present in the log file
    """
    previously_processed_apks = {}
    file_name = "apk_log.txt" # Make file name
    file_path = os.path.join(output_dir, file_name) # Join Path and file name
    if os.path.exists(file_path) and os.path.getsize(file_path): # Check if the file is there and that it's not empty
        try:
            with open(file_path, 'r') as f: # try opening
                for line in f: 
                    if line.strip: # Ignore Empty Lines (just to be safe) 
                        previously_processed_apks[line.strip()] = True # add empty lines to dictionary of correct type
        except Exception as e:
            print(f"Error reading log file: {e}")
    else:
        print(f'INFO: {file_name} has not been created yet or was empty\n')
    return previously_processed_apks
    
def display_list(list): # TODO: should work with dicts and lists when implicitly defined but this is bad practice I think
    """
        Displays a list in a cleaner format

        Args:
            list: Right now this is a list but should work with any iterable object
    """

    for i in list:
        print(i)
    print()
       
if __name__ == "__main__":
    
    # Ensure the test path is defined before running
    if not os.path.exists(DEFAULT_TEST_APK_PATH):
        print(f"ERROR: File not found at specified path (DEFAULT_TEST_APK_PATH): {DEFAULT_TEST_APK_PATH}")
    elif not DEFAULT_TEST_APK_PATH.lower().endswith(".apk"):
        print(f"ERROR: Test file must have a '.apk' extension. Path: {os.path.basename(DEFAULT_TEST_APK_PATH)}")
    else:
        reload_unique_features(os.path.join(DEFAULT_TEST_OUTPUT_DIR_UNIQUE))
        extracted_features = extract_features(DEFAULT_TEST_APK_PATH)
        if extracted_features:
            write_features(extracted_features, DEFAULT_TEST_APK_PATH, DEFAULT_TEST_OUTPUT_DIR_FEATURES)
            update_unique_features(extracted_features, DEFAULT_TEST_OUTPUT_DIR_UNIQUE)
        else:
            print("Extraction returned no features.")

