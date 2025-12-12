"""
GetUniqueFeatures.py
    Reads a feature dataset and writes it's unique features
    Does not alter the dataset
"""
import os

from collections import defaultdict

import ReduceCardinality
import FeatureExtractor

ROOT_DIRECTORY = r'..\dataset_features\subsets\1'
DIRECTORY_UNIQUE = r'unique_features'
DIRECTORY_BENIGN = r'benign_features'
DIRECTORY_MALICIOUS = r'malicious_features'

total_files = 0
TOTAL_FILES_NAME = r"total_files.txt"
file_totals = defaultdict(int)
FILE_TOTALS_NAME = r"file_totals.txt"

# TODO: Quick and dirty, should be it's own function, should traverse more elegantly, combine both loops later
if os.path.exists(ROOT_DIRECTORY): 
    benign_dir = os.path.join(ROOT_DIRECTORY, DIRECTORY_BENIGN)
    malicious_dir = os.path.join(ROOT_DIRECTORY, DIRECTORY_MALICIOUS)
    unique_dir = os.path.join(ROOT_DIRECTORY, DIRECTORY_UNIQUE) 
    unique_features = FeatureExtractor.feature_dictionary() # Making a feature_dictionary   

    if not os.path.exists(unique_dir):
                os.makedirs(unique_dir)
    for _, _, filenames in os.walk(benign_dir): 
        total_files += len(filenames)
        for filename in filenames:
            file_path = os.path.join(benign_dir, filename)
            features = ReduceCardinality.read_feature_file(file_path) # read the features
            unique_features = ReduceCardinality.update_unique_features(features, unique_features) # update unique features
            
    for _, _, filenames in os.walk(malicious_dir): 
        total_files += len(filenames)
        for filename in filenames:
            file_path = os.path.join(malicious_dir, filename)
            features = ReduceCardinality.read_feature_file(file_path) # read the features
            unique_features = ReduceCardinality.update_unique_features(features, unique_features)

    ReduceCardinality.write_unique_features(unique_dir, unique_features) # Also collects counts and adds to the total number of features for each file
    ReduceCardinality.write_totals(ROOT_DIRECTORY) # Writes total number of files and the total number of features for each file
    print(f"Unique Features Extracted")
else:
    print(f"Input directory does not exist: {ROOT_DIRECTORY}\nNo files Processed")