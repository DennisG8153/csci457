import os

def list_files(directory):
    return os.listdir(directory)
def main():
    directory = input("Enter the directory path: ")
    if os.path.isdir(directory):
        files = list_files(directory)
        print("Files in directory:", files)
    else:
        print("The specified path is not a directory.")