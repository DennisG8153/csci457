import os

FEATURE_FILES_PATH = r'apk_features' #r'..\..\apk_features'
DATASET_PATH = r'..\Datasets\amd_data'
feature_file_list = []
dataset_files = []

print('start')

#collect all feature files

for root, dirs, filenames in os.walk(FEATURE_FILES_PATH):
    for name in filenames:
        feature_file_list.append(name.replace('.txt', ''))

for root, dirs, filenames in os.walk(DATASET_PATH):
    for name in filenames:
        dataset_files.append(name)

missed_set = set(dataset_files) - set(feature_file_list)

for i in missed_set:
    print(i)



