import csv
import os

# Change to select specific directories
input_file = "latest.csv"
output_file = "latest_clean.csv"
input_dir = os.path.dirname(__file__)
output_dir = os.path.dirname(__file__)
input_path = os.path.join(input_dir, input_file)
output_path = os.path.join(output_dir, output_file)

def is_ascii(s):
    try:
        s.encode('ascii')
        return True
    except UnicodeEncodeError:
        return False

with open(input_path, 'r', encoding='utf-8', errors='ignore') as infile, \
     open(output_path, 'w', newline='', encoding='utf-8') as outfile:
    reader = csv.reader(infile)
    writer = csv.writer(outfile)
    header = next(reader) # TODO: Header is messed up from original
    writer.writerow(header)
    for row in reader:
        if all(is_ascii(cell) for cell in row):
            writer.writerow(row)