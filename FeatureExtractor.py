# FeatureExtractor.py
# Some feature extraction functions, meant to be used with ExtractWithProgress.py
# Run Directly to extract from a single file to a test directory
# Extracts features from an apk 
# Writes features to a file
# Updates a unique features file
# Reload features from a file into the unique_features dictionary

import os
#from androguard.misc import AnalyzeAPK # APK analysis
from androguard.core.apk import APK # Simpler but faster analysis, doesn't give us everything
from typing import Dict, List # dict to retain insertion order
# from collections import defaultdict # TODO: may use default dict

UNIQUE_FEATURES_FILENAME = "unique_features.txt"

# NOTE: Directory Path to test extracting a single file, change to extract from a different file
DEFAULT_TEST_APK_PATH = r"..\Datasets\Malicious\amd_data\DroidKungFu\variety2\0c3df9c1d759a53eb16024b931a3213a.apk"
#DEFAULT_TEST_APK_PATH = r"..\Datasets\Malicious\amd_data\DroidKungFu\variety2\01c3cc236c3587d20584ed84751c655c.apk"
#DEFAULT_TEST_APK_PATH = r"..\Datasets\Malicious\amd_data\Finspy\variety1\4eea2753d42fef7dc74ea1c8350c659e.apk"
DEFAULT_TEST_OUTPUT_DIR_FEATURES = r"..\test_extracted_features\malicious_features"
DEFAULT_TEST_OUTPUT_DIR_UNIQUE = r"..\test_extracted_features\unique_features"

# Dictionary to store all unique features found across every apk
# Retains insertion order
# TODO: May switch to bool to count
unique_features: Dict[str, bool] = {}

def extract_features(apk_path: str) -> List[str]: # TODO: consider changing to a dict to prevent issues with duplicates
    """
    Extracts features from an apk file and returns them as a List

    Extracted Features:
        TODO: API Calls - Calls to external APIs
        Permissions - Permission requests to parts of device data
        Used Features - Requests for usage to device Hardware and Software functionality
        TODO: Used Intents - Accesses to intents sent/recieved by the application to/from the system, or other applications
        TODO: External Libraries - Use of external libraries within the application
        NOTE: URL - Omitting URL because, of it's high cardinality, it won't be useful to analyze in one piece

    Args:
        apk_path (str): The path to the APK file.
        
    Returns:
        List[str]: A list of the extracted features the APK.
    """

    # Extract Features
    extracted_features: List[str] = []
    try:
        # Load the APK file using androguard's APK class
        a = APK(apk_path)
        #a, d, dx = AnalyzeAPK(apk_path)
        
        # Extract Features

        permissions = a.get_permissions()
        hardware_software = a.get_features()
        # Used Intents TODO
        
        # Put features in extracted_features with labels TODO: Might not need labels
        for p in permissions:
            extracted_features.append(f"Permission: {p}")
        for hs in hardware_software:
            extracted_features.append(f"Used Features: {hs}")
        
    except FileNotFoundError:
        print(f"Error: APK file not found at path: {apk_path}")
        return []
    except Exception as e:
        print(f"Error processing APK {apk_path}: {e}")
        return []
    
    return extracted_features
    
def write_features(extracted_features: List[str], apk_path: str, output_dir: str):
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
        
    # Creating the file path to write to    
    output_filepath = os.path.join(output_dir, f"{os.path.basename(apk_path)}.txt")

    # Write Features to File
    try:
        with open(output_filepath, 'w') as f:
            for feature in extracted_features:
                f.write(f"{feature}\n")
    except Exception as e:
        print(f"Error writing features for {apk_path}: {e}")

def update_unique_features(features: List[str], output_dir: str):
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
    output_filepath = os.path.join(output_dir, UNIQUE_FEATURES_FILENAME)

    try:
        with open(output_filepath, 'a') as f:
            for feature in features:
                if feature not in unique_features:
                    # IF THE FEATURE IS NEW, Add feature to UNIQUE_FEATURES and append it to the file
                    unique_features[feature] = True
                    f.write(f"{feature}\n")         
    except Exception as e:
        print(f"Error appending to unique features file: {e}")
    
def reload_unique_features(output_dir: str):
    """
        Reloads unique features from a text file into UNIQUE_FEATURES dictionary.   
        Looks for subfolder and file: "\\unique_features\\unique_features.txt"
        
        Args:
            output_dir (str): Location where to find the existing unique_features.txt file
    """
    global unique_features #TODO: make sure this stays initialized for each extracted file

    # Join Path and Filename
    file_path = os.path.join(output_dir, UNIQUE_FEATURES_FILENAME)

    # If the unique_features file exists open it and read from it
    if os.path.exists(file_path) and os.path.getsize(file_path) != 0:
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    if line.strip: # Ignore Empty Lines (just to be safe) TODO: Check if there are issues or problems within the unique features file, Throw Error or correct them
                        unique_features[line.strip()] = True
        except Exception as e:
            print(f"Error reading unique_features: {e}")
    else:
        print('INFO: unique_features.txt has not been created yet. No features loaded.')      
    
def display_list(list): # TODO: should work with dicts and lists when implicitly defined but this is bad practice
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

