import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import time
import os
import FeatureExtractor

# NOTE: Set the desired directory to extract from
ROOT_DIRECTORY = r'..\Datasets\amd_data'
UPDATE_INTERVAL_MS = 50 # GUI update rate 

# Trackers for progress bars
total_dirs = 0
total_files = 0
current_dir_count = 0 
current_file_count = 0
current_dir_max_files = 0
files_processed = 0 

# Sum to track total time spent processing files
start_time = 0
proc_times_running_total = 0
last_update_time = 0 

# UI 
window = None
main_progress_bar = None
sub_progress_bar = None

task_label = None
main_progress_label = None
current_file_label = None 
cwd_label = None # current working directory
timer_files_label = None
etr_label = None # estimated time remaining

# Loop Vars
current_dir_path = ""
current_file_list = []
all_files_to_process = []

def preprocess_dir(root_path):
    
    # Pre-scans the directory to calculate totals and makes a file list
    # Returns: (Total Directories, Total Files, File List)
        
    dir_count = 0
    file_count = 0
    file_list = []

    # Scan directories
    for dirpath, dirnames, filenames in os.walk(root_path):
        dir_count += len(dirnames) # Count subdirectories
        # Only count apk files
        valid_filenames = [f for f in filenames if f.lower().endswith('.apk')]
        file_count += len(valid_filenames)
        if valid_filenames: #or not dirnames: # Add the entry if it contains apk files. NOTE: For some reason it was suggest that we also add if the folder is empty. This shouldn't be necessary
            file_list.append((dirpath, valid_filenames))

    # The total number of steps in the first bar is the number of directories
    total_dirs = len(file_list) 
    total_files = file_count
    
    if total_dirs == 0:
        # Check if root path has files but no subdirs, still treat as one step
        if not total_files:
            # Handle case where directory is empty
            print(f"Directory {root_path} is empty. Task completed.")
            return 0, 0, iter([])
        
    return total_dirs, total_files, file_list

def create_window():
    
    # Initializes window, calls update_gui
    # Returns None

    global window

    window.title("Feature Extraction")
    window.geometry("450x280") 
    
    # Center window on screen
    x = (window.winfo_screenwidth() / 2) - (450 / 2)
    y = (window.winfo_screenheight() / 2) - (50 / 2)
    window.geometry(f"+{int(x)}+{int(y)}")

    update_gui()


def calculate_etr():

    # Calculates and updates the Estimated Time Remaining
    # Returns None

    global etr_label

    # Check if no files processed
    if not files_processed:
        etr_label.config(text="Approximate Time Remaining: Calculating...")
        return
        
    average_time_per_file = proc_times_running_total / files_processed
    files_remaining = total_files - files_processed
    time_remaining_seconds = files_remaining * average_time_per_file
    
    etr_hours = int(time_remaining_seconds // 60)
    etr_minutes = int((time_remaining_seconds // 60) % 60)
    etr_seconds = int(time_remaining_seconds % 60)
    
    etr_label.config(text=f"Approximate Time Remaining: {etr_hours:02d}h {etr_minutes:02d}m {etr_seconds:02d}s")

def update_gui():

    # Updates GUI
    # Returns None

    global window, task_label, main_progress_label, current_file_label 
    global main_progress_bar, sub_progress_bar, timer_files_label, cwd_label, etr_label

    # Task Label 
    task_label = ttk.Label(window, text="Extracting Features from APK Files", font=('Helvetica', 14, 'bold'))
    task_label.pack(pady=(15, 5))

    # Folder Progress Bar 
    root_folder_name = os.path.basename(ROOT_DIRECTORY)
    main_progress_label = ttk.Label(window, text=f"Progress in <{root_folder_name}>: 0/{total_dirs} directories", font=('Helvetica', 10))
    main_progress_label.pack(pady=(10, 2))
    
    main_progress_bar = ttk.Progressbar(window, orient="horizontal", length=400, mode="determinate")
    main_progress_bar.pack(pady=5)
    main_progress_bar['maximum'] = total_dirs
    main_progress_bar['value'] = 0

    # Current Folder Label 
    cwd_label = ttk.Label(window, text="Current Folder: ---", font=('Helvetica', 10))
    cwd_label.pack(pady=(5, 2)) 
    
    # Sub-Task Progress Bar 
    sub_progress_bar = ttk.Progressbar(window, orient="horizontal", length=400, mode="determinate")
    sub_progress_bar.pack(pady=5)
    sub_progress_bar['maximum'] = 1 
    sub_progress_bar['value'] = 0

    # Current File Label 
    current_file_label = ttk.Label(window, text="Current File: ---", font=('Helvetica', 10, 'italic'))
    current_file_label.pack(pady=(5, 2))
    
    # Timer/Files Label 
    timer_files_label = ttk.Label(window, text="Time: 00:00:00 | Files Processed: 0/0", font=('Helvetica', 10, 'italic'))
    timer_files_label.pack(pady=10)

    # Estimated Time Remaining Label 
    etr_label = ttk.Label(window, text="Approximate Time Remaining: Calculating...", font=('Helvetica', 10, 'bold'))
    etr_label.pack(pady=5)

if __name__ == "__main__":
    # Scan directory for files
    total_dirs, total_files, all_files_to_process = preprocess_dir(ROOT_DIRECTORY)
    if total_files: # If there are files then proceed with extraction
        # Initialize window and UI
        create_window()
        # Start the extraction after window is fully initialized
        #window.after(10, start_extraction())
        window.mainloop()
    else:
        print('Extraction Canceled: Directory contains no files')