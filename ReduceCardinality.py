# ReduceCardinality.py
# Reduces the Cardinality of a Feature Set by counting the amount of times a feature is used in the Feature Set
# Features are removed if:
# They only occur once (n <= 1)
# They are used by every APK in the Data Set (n == len(Data Set))


import os
from typing import Dict, List
# from collections import defaultdict # TODO: may use default dict
import FeatureExtractor # imported for reload_unique_features(in_dir: str)

ROOT_DIRECTORY = r'..\extracted_features'
IN_DIRECTORY_UNIQUE = r'unique_features'
IN_DIRECTORY_BENIGN = r'benign_features'
IN_DIRECTORY_MALICIOUS = r'malicious_features'
OUT_DIRECTORY_UNIQUE = r'reduced_unique_features'

total_files = 0 # Count of total files in benign_features and malicious_features

def count_total_features(root_path: str):
    """
        Counts the number of times each feature appears in the corpus.
        Assumes all APK features have been extracted.
        Directly edits the global unique_features variable.

    Args: 
        root_path - Designates the folder to look for features in. Requires the folder to contain three directories: benign_features, malicious_features, unique_features
    """
 
    global total_files

    # Create all paths
    in_unique_path = os.path.join(root_path, IN_DIRECTORY_UNIQUE)
    in_benign_path = os.path.join(root_path, IN_DIRECTORY_BENIGN)
    in_malicious_path = os.path.join(root_path, IN_DIRECTORY_MALICIOUS)

    # Check that paths all exist
    if (os.path.exists(in_unique_path) 
    and os.path.exists(in_benign_path) 
    and os.path.exists(in_malicious_path)):
        
        # Reload Unique features into a dictionary, every feature is initialized to 0
        FeatureExtractor.reload_unique_features(in_unique_path)

        # --- BEGIN COUNTING ---

        # TODO: Current folder structure requires us to have two loops, inelegant
        # --- COUNT BENIGN ---
        for _, _, filenames in os.walk(in_benign_path): # Look for files in benign folder
            total_files += len(filenames) # add the number of files in the directory to the total_files count
            for filename in filenames: 
                file_path = os.path.join(in_benign_path, filename) # Get each file name and create the path to it
                with open(file_path, 'r') as features_file: 
                    for feature in features_file: 
                        for feature_type, feature_tag in zip(FeatureExtractor.FEATURE_TYPES, FeatureExtractor.FEATURE_TAGS): # NOTE: zip() returns a tuple containing the elements from each list that have the same indeces 
                            if feature.startswith(feature_tag): # Check each line to see which feature_type it belongs to
                                FeatureExtractor.unique_features[feature_type][feature] += 1 # When the corresponding feature is found add 1 to it's count

        # --- COUNT MALICIOUS ---
        for _, _, filenames in os.walk(in_malicious_path): # Look for files in malicious folder
            total_files += len(filenames) # add the number of files in the directory to the total_files count
            for filename in filenames: 
                file_path = os.path.join(in_malicious_path, filename) # Get each file name and create the path to it
                with open(file_path, 'r') as features_file: 
                    for feature in features_file: 
                        stripped_feature = feature.strip()
                        for feature_type, feature_tag in zip(FeatureExtractor.FEATURE_TYPES, FeatureExtractor.FEATURE_TAGS): # NOTE: zip() returns a tuple containing the elements from each list that have the same indeces 
                            if stripped_feature.startswith(feature_tag): # Check each line to see which feature_type it belongs to
                                FeatureExtractor.unique_features[feature_type][stripped_feature] += 1 # When the corresponding feature is found add 1 to it's count

        print("Unique features counted successfully")
    else:
        print("The following directories do not exist:" + ((f"\n{in_unique_path}") if not os.path.exists(in_unique_path) else "") 
                                                        + ((f"\n{in_benign_path}") if not os.path.exists(in_benign_path) else "")
                                                        + ((f"\n{in_malicious_path}") if not os.path.exists(in_malicious_path) else ""))
        print("No files processed")
    
def write_reduced_unique_features(root_path: str):
    """
        Writes the features to a new file (reduced_unique_features)
        Ommits features that only appear once or appear for every apk file
        unique_features dictionary must be initialized

    Args: 
        out_path - Designates the folder to where the feature files are, creates and writes to reduced_unique_features folder
    """

    # Check if root path exists
    if os.path.exists(root_path): 
        # Creates output path and make sure it exists, if it doesn't, create it
        out_path = os.path.join(root_path, OUT_DIRECTORY_UNIQUE)
        if not os.path.exists(out_path):
            os.makedirs(out_path)
        
        # Walks the dictionary and writes a feature to the coresponding file if: 1 < feature count < number of apk files
        if len(FeatureExtractor.unique_features):
            for feature_type in FeatureExtractor.unique_features: # NOTE: features in all files already contain feature tags, tags are added when they are extracted
                file_path = os.path.join(out_path, "unique_" + feature_type + ".txt")
                try:
                    with open(file_path, 'w') as file:
                        for feature in FeatureExtractor.unique_features[feature_type]:
                            if 1 < FeatureExtractor.unique_features[feature_type][feature] and FeatureExtractor.unique_features[feature_type][feature] < total_files:
                                file.write(f"{feature.strip()}\n")
                except Exception as e:
                    print(f"Error opening {file_path}\nException: {e}")
        else:
            print("Dictionary Length Mismatch:")
            print(f"Length of unique_features: {len(FeatureExtractor.unique_features)}")
            print(f"Length of FEATURE_TYPES: {len(FeatureExtractor.FEATURE_TYPES)}")
            print(f"Length of FEATURE_TAGS: {len(FeatureExtractor.FEATURE_TAGS)}")
        
        print("Unique features written successfully")
    else:
        print(f"Input path does not exist:\n{root_path}\nNo unique features written") 

if __name__ == '__main__':
    print("Attempting to reduce feature cardinality")
    FeatureExtractor.reload_unique_features(os.path.join(ROOT_DIRECTORY, IN_DIRECTORY_UNIQUE))
    count_total_features(ROOT_DIRECTORY)
    write_reduced_unique_features(ROOT_DIRECTORY)