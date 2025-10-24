import os

FEATURE_FILES_PATH = r'..\..\apk_features'
DATASET_PATH = r'..\..\Datasets\amd_data'
feature_file_list = []
dataset_files = []

#collect all feature files

for root, dirs, filenames in os.walk(FEATURE_FILES_PATH):
    for name in filenames:
        feature_file_list.append(name.replace('.txt', ''))

for root, dirs, filenames in os.walk(DATASET_PATH):
    for name in filenames:
        dataset_files.append(name)

print(str(set(dataset_files) - set(feature_file_list)))



