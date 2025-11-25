import os
from collections import defaultdict

unique_list = defaultdict(int)
dup_list = None
dup_count = 0
total_files = 0

# NOTE: This path changes depending if you have the project open or the folder for this file open
for root, dirs, filenames in os.walk(r"..\..\Datasets\Benign"):
    #print(filenames)
    #for dir in dirs:
    for name in filenames:
        #print(name)
        unique_list[name] += 1
        if unique_list[name] > 1:
            dup_count += 1
        total_files += 1

print('Total Files: ' + str(total_files))
print('Dupe Count: ' + str(dup_count))
print('Duped Files: ')

for name in unique_list:
    if unique_list[name] > 1:
        print('name: ' + name + ' Value: ' + str(unique_list[name]))
