import tkinter as tk
from tkinter import ttk
#from tkinter import messagebox
import time
import os
import gc
import FeatureExtractor 

# TODO: add a way to pick up from were we previously left of with each features file, currently unique_features does this, but not each individual file

# NOTE: Set the desired directory to extract from. 
OUT_DIRECTORY = r'..\extracted_features'
#OUT_DIRECTORY = r'..\test_extracted_features'
OUT_DIRECTORY_UNIQUE = os.path.join(OUT_DIRECTORY, 'unique_features')
#CRITICAL NOTE: REMEMBER TO SWAP BETWEEN MALICIOUS AND BENIGN DATA SETS
#'''
ROOT_DIRECTORY = r'..\Datasets\Malicious'
OUT_DIRECTORY_FEATURES = os.path.join(OUT_DIRECTORY, 'malicious_features')
'''
#ROOT_DIRECTORY = r'..\Datasets\Benign'
OUT_DIRECTORY_FEATURES = os.path.join(OUT_DIRECTORY, 'benign_features')
'''
ROOT_DIRECTORY_NAME = {os.path.basename(ROOT_DIRECTORY)} # Just for main_progress_label in the UI

# Trackers for progress bars
TOTAL_DIR_COUNT = 0
TOTAL_FILE_COUNT = 0
total_files_processed = 0 
total_dirs_processed = 0 
current_dir_file_count = 0
current_dir_total_file_count = 0

# Loop Vars
DIR_FILE_LIST = []
current_dir_file_list = []
current_dir_path = ''
current_file_path = ''
current_file_name = ''

# Times to track total time spent processing files
START_TIME = 0
elapsed_time = 0

# UI 
WINDOW = None
WINDOW_DIMENSIONS = '450x280'
main_progress_bar = None
sub_progress_bar = None

TITLE_LABEL = 'Feature Extraction'
TASK_LABEL = 'Extracting Features from APK Files'
main_progress_label = None
cwd_label = None # current working directory
current_file_label = None 
timer_files_label = None
etr_label = None # estimated time remaining

def preprocess_dir():
    '''        
    Pre-scans the directory to calculate totals and makes a file list   
    Returns: None
    '''

    global TOTAL_DIR_COUNT, TOTAL_FILE_COUNT, DIR_FILE_LIST

    # Temp variables so that global variables are only edited once, therefore no accidental changes can be main during instantiation 
    total_dirs = 0
    total_files = 0
    dir_file_list = []
    #previously_processed_apks = FeatureExtractor.reload_processed_apks(OUT_DIRECTORY)

    # Scan directories
    for dirpath, _, filenames in os.walk(ROOT_DIRECTORY):
        # NOTE: DREBINS FILES DO NOT END WITH APK
        #valid_filenames = [f for f in filenames if f.lower().endswith('.apk')]
        previously_processed_apks = FeatureExtractor.reload_processed_apks(OUT_DIRECTORY)
        unprocessed_apks = []
        for filename in filenames:
            if filename.strip() not in previously_processed_apks:
                unprocessed_apks.append(filename.strip())
        total_files += len(unprocessed_apks)
        if unprocessed_apks: # Add the entry if it contains apk files
            dir_file_list.append((dirpath, unprocessed_apks))   
    total_dirs = len(dir_file_list)  # The total number of steps in the first bar is the number of directories WITH files to process
        
    TOTAL_DIR_COUNT = total_dirs
    TOTAL_FILE_COUNT = total_files
    DIR_FILE_LIST = dir_file_list

def calculate_etr():

    # Calculates and updates the Estimated Time Remaining
    # Returns: None

    global etr_label, elapsed_time
        
    average_time_per_file = elapsed_time / (total_files_processed if total_files_processed else 1)
    files_remaining = TOTAL_FILE_COUNT - total_files_processed
    time_remaining_seconds = files_remaining * average_time_per_file
    
    etr_hours = int(time_remaining_seconds // 3600)
    etr_minutes = int((time_remaining_seconds // 60) % 60)
    etr_seconds = int(time_remaining_seconds % 60)
    
    etr_label.config(text=f"Approximate Time Remaining: {etr_hours:02d}h {etr_minutes:02d}m {etr_seconds:02d}s")

def update_gui(): 
    global main_progress_bar, sub_progress_bar
    global main_progress_label, current_file_label, timer_files_label, cwd_label
    global total_files_processed, current_dir_path, total_dirs_processed, current_dir_file_count, current_dir_total_file_count, elapsed_time

    hours = int(elapsed_time // 3600)
    minutes = int((elapsed_time // 60) % 60)
    seconds = int(elapsed_time % 60)

    main_progress_label.config(text=f"Progress in <{ROOT_DIRECTORY_NAME}>: {total_dirs_processed} / {TOTAL_DIR_COUNT} Folders | {total_files_processed}/{TOTAL_FILE_COUNT} Files")
    main_progress_bar['value'] = total_files_processed

    cwd_label.config(text=f"Current Folder: {current_dir_path}")
    sub_progress_bar['maximum'] = current_dir_total_file_count
    sub_progress_bar['value'] = current_dir_file_count

    current_file_label.config(text=f"Current File: {current_file_name}")
    timer_files_label.config(text=f"Time: {hours:02d}:{minutes:02d}:{seconds:02d} | Files in Directory: {current_dir_file_count}/{current_dir_total_file_count}")
    calculate_etr()

    #print('GUI')

def create_window():
    
    # Initializes window, calls update_gui
    # Returns None

    global WINDOW, main_progress_bar, sub_progress_bar
    global main_task_label, main_progress_label, current_file_label, timer_files_label, cwd_label, etr_label
    global current_dir_total_file_count

    WINDOW = tk.Tk()
    WINDOW.title(TITLE_LABEL)
    WINDOW.geometry(WINDOW_DIMENSIONS) 
    
    # Center window on screen, sort of
    x = (WINDOW.winfo_screenwidth() / 2) - (450 / 2)
    y = (WINDOW.winfo_screenheight() / 2) - (50 / 2)
    WINDOW.geometry(f"+{int(x)}+{int(y)}")
    
    # Title Label 
    main_task_label = ttk.Label(WINDOW, text=TASK_LABEL, font=('Helvetica', 14, 'bold'))
    main_task_label.pack(pady=(15, 5))

    # Folder Progress
    # Folder Progress Label
    main_progress_label = ttk.Label(WINDOW, text=f"Progress in <{ROOT_DIRECTORY_NAME}>: -/- directories", font=('Helvetica', 10))
    main_progress_label.pack(pady=(10, 2))
    
    # Folder Progress Bar
    main_progress_bar = ttk.Progressbar(WINDOW, orient="horizontal", length=400, mode="determinate")
    main_progress_bar.pack(pady=5)
    main_progress_bar['maximum'] = TOTAL_FILE_COUNT
    main_progress_bar['value'] = 0

    # Files in Folder Progress
    # Current Folder Label (Current working directory)
    cwd_label = ttk.Label(WINDOW, text="Current Folder: ---", font=('Helvetica', 10))
    cwd_label.pack(pady=(5, 2)) 
    
    # Files in Folder Progress Bar 
    sub_progress_bar = ttk.Progressbar(WINDOW, orient="horizontal", length=400, mode="determinate")
    sub_progress_bar.pack(pady=5)
    sub_progress_bar['maximum'] = 1 
    sub_progress_bar['value'] = 0

    # Current File Label 
    current_file_label = ttk.Label(WINDOW, text="Current File: ---", font=('Helvetica', 10, 'italic'))
    current_file_label.pack(pady=(5, 2))
    
    # Timer/Files in Folder Label 
    timer_files_label = ttk.Label(WINDOW, text="Time: --:--:-- | Files Processed: -/-", font=('Helvetica', 10, 'italic'))
    timer_files_label.pack(pady=10)

    # Estimated Time Remaining Label 
    etr_label = ttk.Label(WINDOW, text="Approximate Time Remaining: ---", font=('Helvetica', 10, 'bold'))
    etr_label.pack(pady=5)

def extract_with_progress():
    
    global total_files_processed, total_dirs_processed, current_dir_file_count, current_dir_total_file_count, elapsed_time
    global current_dir_file_list, current_dir_path, current_file_path, current_file_name

    # Check if we are done with files in the current folder
    if current_dir_file_count >= current_dir_total_file_count:

        # Increment total_dirs_count
        total_dirs_processed += 1

        # if done with every dir don't do anything else
        if total_dirs_processed >= TOTAL_DIR_COUNT:
            return
        
        # reset current_dir_file_count
        current_dir_file_count = 0

        # Switch path to next dir, switch file list to next dir's file list, set next dir's current_dir_total_file_count
        current_dir_path, current_dir_file_list = DIR_FILE_LIST[total_dirs_processed]
        current_dir_total_file_count = len(current_dir_file_list)

        update_gui()
        WINDOW.update()
        # Restart loop for next directory
        WINDOW.after(0, extract_with_progress)
        return

    # Gets file to extract
    current_file_name = current_dir_file_list[current_dir_file_count]
    current_file_path = os.path.join(current_dir_path, current_file_name)



    # Extraction and Writing to files
    extracted_features = FeatureExtractor.extract_features(current_file_path)
    
    # Update unique features tracking 
    if extracted_features:
        FeatureExtractor.write_features(extracted_features, current_file_path, OUT_DIRECTORY_FEATURES)
        FeatureExtractor.update_unique_features(extracted_features, OUT_DIRECTORY_UNIQUE)

    # File extracted, update elapsed time
    elapsed_time = time.time() - START_TIME

    # Increment file counters
    current_dir_file_count += 1
    total_files_processed += 1

    gc.collect # Invoke trash collector Don't know if there is a build up of data but will try this

    # NOTE: Updating gui can only occur during the next .after() call, 
    update_gui()
    WINDOW.update()
    # Next iteration, next file in the directory
    WINDOW.after(0, extract_with_progress)

def extraction_setup():
    # Set up initial values for recursive loop extract_with_progress

    global START_TIME
    global total_dirs_processed, current_dir_file_count, current_dir_total_file_count
    global current_dir_file_list, current_dir_path, current_file_name

    # Set initial directory for extraction and first file name
    current_dir_path, current_dir_file_list = DIR_FILE_LIST[total_dirs_processed]
    current_dir_total_file_count = len(current_dir_file_list)

    # Reload unique_features.txt 
    FeatureExtractor.reload_unique_features(OUT_DIRECTORY_UNIQUE)


    update_gui()
    WINDOW.update() # Opens window immediately
    # START_TIME set right before extraction begins  
    START_TIME = time.time() 
    WINDOW.after(0, extract_with_progress())

if __name__ == '__main__': 
    if os.path.isdir(ROOT_DIRECTORY):
        preprocess_dir()
        if TOTAL_FILE_COUNT:
            create_window()
            # Must be in this order, 
            # after() sets the next action of the window, 
            # mainloop() starts the window and then the action is taken
            WINDOW.after(0, extraction_setup())
            WINDOW.mainloop()

        else:
            print('Extraction Canceled: Directory contains no files')
    else:
        print('Extraction Canceled: Directory not found')