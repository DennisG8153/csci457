import os
from collections import defaultdict

unique_list = defaultdict(list)
dup_list = None
dup_count = 0
total_files = 0

for root, dirs, filenames in os.walk(r'..\Datasets\amd_data'):
    #print(filenames)
    #for dir in dirs:
    for name in filenames:
        #print(name)
        if name in unique_list:
            unique_list[name] += 1
            dup_count += 1
        else:
            unique_list[name] = 0
        total_files += 1

print('Total Files ' + str(total_files))
print('dup_count ' + str(dup_count))

for name in unique_list:
    if unique_list[name] > 0:
        print('name: ' + name + 'Value: ' + str(unique_list[name]))
