# FeatureExtractor.py
# Two feature extraction functions, meant to be used with ExtractWithProgress.py
# Run Directly to extract from a single file to a test directory
# Extracts and writes features from one apk to a file
# Updates a unique features file

import os
from androguard.core.apk import APK # APK analysis
from typing import Dict, List # dict to retain insertion order
# from collections import defaultdict # may use default dict

# --- Output Directory Configuration ---
# These directories will be created relative to the execution location of the calling script (progress_popup.py)
APK_FEATURES_OUTPUT_DIR = "malicious_apk_features"
#APK_FEATURES_OUTPUT_DIR = "benign_apk_features"
UNIQUE_FEATURES_OUTPUT_DIR = "unique_features"
UNIQUE_FEATURES_FILENAME = "unique_features.txt"

# NOTE: Directory Path to test extracting a single file
DEFAULT_TEST_APK_PATH = r"..\Datasets\Malicious\amd_data\DroidKungFu\variety2\0a34d14be275ef9fc3227716a5c3b85b.apk"
DEFAULT_TEST_OUTPUT_DIR = r"..\test_extracted_features"

# Dictionary to store all unique features found across every apk
# Retains insertion order
# Key: Feature name
# Value: Boolean (feature was found)
UNIQUE_FEATURES: Dict[str, bool] = {}

def extract_features_and_write(apk_path: str, output_dir: str) -> List[str]:
    """
    Extracts features and writes them to a file that shares a name with the apk with '.txt' appended
    Extracted Features:
        Permissions - Permission requests to parts of device data
        TODO: API Calls - Calls to external APIs
        TODO: Used Features - Requests for usage to device Hardware and Software functionality
        TODO: Used Intents - Accesses to intents sent/recieved by the application to/from the system, or other applications
        TODO: URL - Connections to websites
        TODO: External Libraries - Use of external libraries within the application
    
    Args:
        apk_path (str): The path to the APK file.
        output_dir (str): The directory where the output folders will be created.
        
    Returns:
        List[str]: A list of the extracted features the APK.
    """
    
    # Define Output Path
    output_dir = os.path.join(output_dir, APK_FEATURES_OUTPUT_DIR)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    apk_filename = os.path.basename(apk_path)
    output_filepath = os.path.join(output_dir, f"{apk_filename}.txt")
    
    extracted_features: List[str] = []
    
    # Extract Features
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

    # 3. Write Features (Permissions) to File
    try:
        with open(output_filepath, 'w') as f:
            f.write(f"--- Extracted Features from {apk_filename} ---\n\n")
            for i, feature in enumerate(extracted_features):
                f.write(f"Feature {i+1}: {feature}\n")
        
        return extracted_features
        
    except Exception as e:
        print(f"Error writing features for {apk_path}: {e}")
        return []

def update_unique_features(features: List[str], output_path: str):
    """
    Aggregates new features into the global UNIQUE_FEATURES dictionary and 
    writes the complete list of unique features to 'unique_features.txt'.
    
    Args:
        features (List[str]): A list of features extracted from a single APK.
        base_output_path (str): The root directory where the output folders should be created.
    """
    global UNIQUE_FEATURES
    
    # 1. Update In-Memory Tracking
    for feature in features:
        # Check if the feature is not already in the dictionary
        if feature not in UNIQUE_FEATURES:
            # If not present, add it. This preserves the insertion order.
            UNIQUE_FEATURES[feature] = True
            
    # 2. Write Complete Unique List to File
    output_dir = os.path.join(output_path, UNIQUE_FEATURES_OUTPUT_DIR)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    output_filepath = os.path.join(output_dir, UNIQUE_FEATURES_FILENAME)
    
    try:
        with open(output_filepath, 'a') as f:
            
            for feature in UNIQUE_FEATURES.keys():
                f.write(f"{feature}\n")
                
    except Exception as e:
        print(f"Error writing unique features file: {e}")

def reset_unique_features(file_path: str):
    return


if __name__ == "__main__":
    
    # Ensure the test path is defined before running
    if not os.path.exists(DEFAULT_TEST_APK_PATH):
        print(f"ERROR: File not found at specified path: {DEFAULT_TEST_APK_PATH}")
        
    elif not DEFAULT_TEST_APK_PATH.lower().endswith(".apk"):
        print(f"ERROR: Test file must have a '.apk' extension. Path: {os.path.basename(DEFAULT_TEST_APK_PATH)}")
        
    else:
        extracted_features = extract_features_and_write(DEFAULT_TEST_APK_PATH, DEFAULT_TEST_OUTPUT_DIR)
        if extracted_features:
            update_unique_features(extracted_features, DEFAULT_TEST_OUTPUT_DIR)
        else:
            print("Extraction returned no features.")

