# checkForDuplicates.py
# Checks for dulicate lines in all files in dir
import os

def find_duplicate_lines(filename):
    seen_lines = set()
    duplicate_lines = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip() # Remove leading/trailing whitespace and newline characters
            if line in seen_lines:
                duplicate_lines.append(line)
            else:
                seen_lines.add(line)
    return duplicate_lines

checked_folder = r'..\large_test_extracted_features'

if not os.path.exists(checked_folder):
    print(f"Error: Folder '{checked_folder}' does not exist!")
    exit()

for root, dirs, files in os.walk(checked_folder):
    for txt_file in files:
        if txt_file.endswith(".txt"): #only care about .txt
            txt_path = os.path.join(root, txt_file)
            duplicates = find_duplicate_lines(txt_path)
            if duplicates:
                print(f"Duplicate lines found in '{txt_file}':")
                for dup in set(duplicates): # Use a set to print unique duplicate lines
                    print(dup)
            '''else:
                print(f"No duplicate lines found in '{txt_file}'.")
            print(f"------------------------------------------")'''