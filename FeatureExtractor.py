# FeatureExtractor.py
# Two feature extraction functions, meant to be used with ExtractWithProgress.py
# Run Directly to extract from a single file to a test directory
# Extracts and writes features from one apk to a file
# Updates a unique features file

import os
from androguard.core.apk import APK # APK analysis
from typing import Dict, List # dict to retain insertion order
# from collections import defaultdict # TODO: may use default dict

# NOTE: Default directories output will be sent to. REMEMBER TO SWITCH THIS WHEN SWITCHING TO BENIGN EXTRACTION
# TODO: Add some way to tell function which output directory to use
APK_FEATURES_OUTPUT_DIR = "malicious_apk_features"
#APK_FEATURES_OUTPUT_DIR = "benign_apk_features"
UNIQUE_FEATURES_OUTPUT_DIR = "unique_features"
UNIQUE_FEATURES_FILENAME = "unique_features.txt"

# NOTE: Directory Path to test extracting a single file
DEFAULT_TEST_APK_PATH = r"..\Datasets\Malicious\amd_data\DroidKungFu\variety2\0c3df9c1d759a53eb16024b931a3213a.apk"
DEFAULT_TEST_OUTPUT_DIR = r"..\test_extracted_features"

# Dictionary to store all unique features found across every apk
# Retains insertion order
# TODO: May switch to bool to count
UNIQUE_FEATURES: Dict[str, bool] = {}

def extract_features(apk_path: str) -> List[str]:
    """
    Extracts features from an apk file and returns them as a List

    Extracted Features:
        Permissions - Permission requests to parts of device data
        TODO: API Calls - Calls to external APIs
        TODO: Used Features - Requests for usage to device Hardware and Software functionality
        TODO: Used Intents - Accesses to intents sent/recieved by the application to/from the system, or other applications
        TODO: URL - Connections to websites
        TODO: External Libraries - Use of external libraries within the application
    
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
        
        # Get permissions (the feature we are extracting now)
        permissions = a.get_permissions()
        
        # Format the permissions to include a prefix for clarity and consistency
        extracted_features = [f"Permission: {p}" for p in permissions]
        
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

    # Define Output Path
    output_dir = os.path.join(output_dir, APK_FEATURES_OUTPUT_DIR)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir) # TODO: Not sure if creating the directory is necessary
        
    output_filepath = os.path.join(output_dir, f"{os.path.basename(apk_path)}.txt")

    # Write Features to File
    try:
        with open(output_filepath, 'w') as f:
            for feature in extracted_features:
                f.write(f"{feature}\n")
    except Exception as e:
        print(f"Error writing features for {apk_path}: {e}")

def update_unique_features(features: List[str], output_path: str):
    """
    Aggregates new features into the global UNIQUE_FEATURES dictionary and 
    writes the complete list of unique features to 'unique_features.txt'.
    
    Args:
        features (List[str]): A list of features extracted from a single APK.
        base_output_path (str): The root directory where the output folders should be created.
    """
    global UNIQUE_FEATURES

    # Set output directory path
    output_dir = os.path.join(output_path, UNIQUE_FEATURES_OUTPUT_DIR)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    # Set output file path
    output_filepath = os.path.join(output_dir, UNIQUE_FEATURES_FILENAME)

    try:
        with open(output_filepath, 'a') as f:
            for feature in features:
                if feature not in UNIQUE_FEATURES:
                    # Add new feature to UNIQUE_FEATURES and append it to the file
                    UNIQUE_FEATURES[feature] = True
                    f.write(f"{feature}\n")         
    except Exception as e:
        print(f"Error appending to unique features file: {e}")

def reload_unique_features(output_dir: str):
    """
        Reloads unique features from a text file into UNIQUE_FEATURES dictionary.   
        Looks for subfolder and file: "\\unique_features\\unique_features.txt"
        
        Args:
            output_dir (str): Location where features will be extracted to
    """

    file_path = os.path.join(output_dir, UNIQUE_FEATURES_OUTPUT_DIR, UNIQUE_FEATURES_FILENAME)
    # If the unique_features file exists open it and read from it
    if os.path.exists(file_path) and os.path.getsize(file_path) != 0:
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    if line.strip: # Ignore Empty Lines (just to be safe)
                        UNIQUE_FEATURES[line.strip()] = True
        except Exception as e:
            print(f"Error reading unique_features: {e}")
    else:
        print('INFO: unique_features.txt has not been created yet. No features loaded.')
            

if __name__ == "__main__":
    
    # Ensure the test path is defined before running
    if not os.path.exists(DEFAULT_TEST_APK_PATH):
        print(f"ERROR: File not found at specified path (DEFAULT_TEST_APK_PATH): {DEFAULT_TEST_APK_PATH}")
    elif not DEFAULT_TEST_APK_PATH.lower().endswith(".apk"):
        print(f"ERROR: Test file must have a '.apk' extension. Path: {os.path.basename(DEFAULT_TEST_APK_PATH)}")
    else:
        reload_unique_features(DEFAULT_TEST_OUTPUT_DIR)
        extracted_features = extract_features(DEFAULT_TEST_APK_PATH)
        if extracted_features:
            write_features(extracted_features, DEFAULT_TEST_APK_PATH, DEFAULT_TEST_OUTPUT_DIR)
            update_unique_features(extracted_features, DEFAULT_TEST_OUTPUT_DIR)
        else:
            print("Extraction returned no features.")
    for i in UNIQUE_FEATURES:
        print(i)

