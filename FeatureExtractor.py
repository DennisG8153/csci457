# This module handles the core logic for extracting features 
# from APK files and aggregating unique features across the workflow.
# Renaming module reference to FeatureExtracter.

import os
from androguard.core.apk import APK # Library needed for APK analysis
# Using dict (or OrderedDict if on Python < 3.7) to retain insertion order
from typing import Dict, List 

# --- Output Directory Configuration ---
# These directories will be created relative to the execution location of the calling script (progress_popup.py)
APK_FEATURES_OUTPUT_DIR = "apk_features"
UNIQUE_FEATURES_OUTPUT_DIR = "unique_features"
UNIQUE_FEATURES_FILENAME = "unique_features.txt"

# --- Testing Configuration (Only used when running this file directly) ---
# NOTE: User must change this path to a valid APK file for testing.
DEFAULT_TEST_APK_PATH = r".\testData\0a34d14be275ef9fc3227716a5c3b85b.apk"

# --- Unique Feature Tracking State ---
# This dictionary will store every unique feature encountered across all APKs,
# using the feature name as the key. Standard dicts retain insertion order 
# in Python 3.7+, which fulfills the requirement.
# Value is a simple placeholder (e.g., True) or a count if needed later.
UNIQUE_FEATURES: Dict[str, bool] = {}


def extract_features_and_write(apk_path: str, base_output_path: str) -> List[str]:
    """
    Extracts features (permissions only for now) from an APK file and writes them 
    to a file in the 'apk_features' subdirectory.
    
    Args:
        apk_path (str): The full path to the APK file.
        base_output_path (str): The root directory where the output folders should be created.
        
    Returns:
        List[str]: A list of the extracted features (permissions) for the current APK.
    """
    
    # 1. Define Output Path
    output_dir = os.path.join(base_output_path, APK_FEATURES_OUTPUT_DIR)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    apk_filename = os.path.basename(apk_path)
    output_filepath = os.path.join(output_dir, f"{apk_filename}.txt")
    
    extracted_features: List[str] = []
    
    # 2. Real Feature Extraction: Extract Permissions using androguard
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


def update_unique_features(features: List[str], base_output_path: str):
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
    output_dir = os.path.join(base_output_path, UNIQUE_FEATURES_OUTPUT_DIR)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    output_filepath = os.path.join(output_dir, UNIQUE_FEATURES_FILENAME)
    
    try:
        with open(output_filepath, 'w') as f:
            f.write("--- Unique Features Across All Processed APKs (Ordered by First Appearance) ---\n\n")
            for feature in UNIQUE_FEATURES.keys():
                f.write(f"{feature}\n")
                
    except Exception as e:
        print(f"Error writing unique features file: {e}")


def get_unique_features_count():
    """
    Returns the current number of unique features tracked.
    """
    return len(UNIQUE_FEATURES)


if __name__ == "__main__":
    # Get the directory where this script is located for output files
    base_path = os.path.dirname(os.path.abspath(__file__))

    print("--- Running Feature Extraction Test ---")
    print(f"Base Output Path: {base_path}")
    print(f"Attempting to analyze file: {DEFAULT_TEST_APK_PATH}")
    
    # Ensure the test path is defined before running
    if not os.path.exists(DEFAULT_TEST_APK_PATH):
        print(f"\nERROR: File not found at specified path: {DEFAULT_TEST_APK_PATH}")
        
    elif not DEFAULT_TEST_APK_PATH.lower().endswith(".apk"):
        print(f"\nERROR: Test file must have a '.apk' extension. Found: {os.path.basename(DEFAULT_TEST_APK_PATH)}")
        
    else:
        # Test 1: Extract and Write features for a single APK
        extracted_features = extract_features_and_write(DEFAULT_TEST_APK_PATH, base_path)
        
        if extracted_features:
            print("\nTest 1 Successful!")
            print(f"Extracted {len(extracted_features)} features.")
            print(f"Check the '{APK_FEATURES_OUTPUT_DIR}' folder for the output file.")

            # Test 2: Update Unique Features with the extracted list
            update_unique_features(extracted_features, base_path)
            
            print("Unique features tracking updated.")
            print(f"Total unique features after test: {get_unique_features_count()}")
            print(f"Check the '{UNIQUE_FEATURES_OUTPUT_DIR}' folder for the aggregated file.")
        else:
            print("\nTest 1 Failed: Extraction returned no features.")
