import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import time
import os
import FeatureExtractor #Logic for extracting features

# NOTE: Set the desired directory to extract from
ROOT_DIRECTORY = r'..\Datasets\amd_data'
#UPDATE_INTERVAL_MS = 50 # GUI update rate 

# Trackers for progress bars
total_dirs = 0
total_files = 0
current_dir_count = 0 
current_file_count = 0
current_dir_max_files = 0
total_files_processed = 0 

# Sum to track total time spent processing files
start_time = 0
proc_times_running_total = 0
last_update_time = 0

# UI 
window = None
title = None
main_progress_label = None
main_progress_bar = None
current_file_label = None 
sub_progress_bar = None
cwd_label = None # current working directory
total_files_label = None 
timer_label = None
etr_label = None # estimated time remaining

# Loop Vars
current_dir_path = ""
current_file_list = []
all_files_to_process = []

def preprocess_dir(root_path):
    
    # Pre-scans the directory to calculate totals and makes a file list
    # Returns: (Total Directories, Total Files, File List)
    
    global total_dirs, total_files
    
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
    total_files = file_count # Updates total_files all at once
    
    if total_dirs == 0:
        # Check if root path has files but no subdirs, still treat as one step
        if not total_files:
            # Handle case where directory is empty
            print(f"Directory {root_path} is empty. Task completed.")
            return 0, 0, iter([])
        
    # Return an iterator over the prepared data
    return total_dirs, total_files, file_list

def calculate_etr():
    # Calculates and updates the Estimated Time Remaining
    global etr_label

    # Check if no files processed
    if not total_files_processed:
        etr_label.config(text="Approximate Time Remaining: Calculating...")
        return
        
    average_time_per_file = proc_times_running_total / total_files_processed
    files_remaining = total_files - total_files_processed
    time_remaining_seconds = files_remaining * average_time_per_file
    
    etr_hours = int(time_remaining_seconds // 60)
    etr_minutes = int((time_remaining_seconds // 60) % 60)
    etr_seconds = int(time_remaining_seconds % 60)
    
    etr_label.config(text=f"Approximate Time Remaining: {etr_hours:02d}h {etr_minutes:02d}m {etr_seconds:02d}s")

def update_gui():
    
    # Updates Progress bars and runs extraction
    # Returns null

    global current_dir_path, current_dir_count, current_file_list, current_file_count, total_files_processed, last_update_time
    global current_dir_max_files

    # Update Timer
    elapsed_time = time.time() - start_time
    hours = int(elapsed_time // 360)
    minutes = int((elapsed_time // 60) % 60)
    seconds = int(elapsed_time % 60)
    
    # Update Timer and Total Files Processed
    timer_label.config(text=f"Time: {hours:02d}:{minutes:02d}:{seconds:02d} | Files Processed: {total_files_processed}/{total_files}")
    
    # Check if all directories are done
    if current_dir_count <= total_dirs:
        
        # Check if all files are done
        if current_file_count <= current_dir_max_files:
            
            # Calculate time taken for the last file
            if last_update_time:
                file_process_times += time.time() - last_update_time
            
            # APK FEATURE EXTRACTION
            
            current_apk_filename = current_file_list[current_file_count]
            current_apk_path = os.path.join(current_dir_path, current_apk_filename)
            
            # Call the external function to extract features and write to file
            extracted_features = FeatureExtractor.extract_features_and_write(
                apk_path=current_apk_path,
                base_output_path=os.path.dirname(os.path.abspath(__file__))
            )
            
            # Update unique features tracking
            if extracted_features:
                FeatureExtractor.update_unique_features(
                    features=extracted_features, 
                    base_output_path=os.path.dirname(os.path.abspath(__file__))
                )

            # --- END REAL WORK ---
            
            # Update tracking counts
            current_file_count += 1
            total_files_processed += 1 # Increment total count
            
            # Update timestamp for next calculation
            last_update_time = time.time()

            # Sub-Task Label 
            file_name = current_file_list[current_file_count - 1] if current_file_list else "Processing folder..."
            current_file_label.config(
                text=f"Current File: {file_name} ({current_file_count}/{current_dir_max_files} files)"
            )
            sub_progress_bar['value'] = current_file_count
            
            # Recalculate and update the overall folder bar value
            completed_dirs_value = current_dir_count + (current_file_count / current_dir_max_files if current_dir_max_files else 0)
            main_progress_bar['value'] = completed_dirs_value
            
            # Recalculate and display ETC
            calculate_etr()
            
            # Schedule the next file step (simulated work time)
            window.after(1, update_gui)
            
        else:
            # --- Folder Iteration: Sub-Task Completed, move to Next Directory ---
            try:
                # Get the next directory from the prepared iterator
                dirpath, filenames = next(workflow_iterator) # TODO: THIS NO LONGER WORKS
                
                # Update global state for the next folder
                current_dir_path = dirpath
                current_file_list = filenames
                current_dir_max_files = len(filenames)
                current_dir_count += 1 # Increment overall directory count
                current_file_count = 0 # Reset file counter for the new directory

                # Set bar maximums
                sub_progress_bar['maximum'] = current_dir_max_files if current_dir_max_files else 1
                
                # UPDATE NEW CWD LABEL to show only the folder name
                folder_name = os.path.basename(current_dir_path)
                # Handle the case where the path is the root directory itself (basename might be empty)
                if not folder_name:
                    folder_name = os.path.basename(ROOT_DIRECTORY)
                    
                cwd_label.config(text=f"Current Folder: {folder_name}")

                # Update Folder Progress Label (First Bar)
                main_progress_label.config(
                    text=f"Progress in <{os.path.basename(ROOT_DIRECTORY)}>: {current_dir_count}/{total_dirs} directories"
                )
                
                # Recalculate and display ETC immediately before next step
                calculate_etr()
                
                # Recursively call update_gui immediately to process the first file in the new directory
                window.after(1, update_gui) 
                
            except StopIteration:
                # Iterator is exhausted (should be caught by the outer if, but safe fallback)
                window.after(1, update_gui)
    
    else:
        # Directories traversed, Extration done
        
        # COMBINED STAT: Time Elapsed and Total Files Processed
        final_stat_str = (
            f"Time Elapsed: {hours:02d}h {minutes:02d}m {seconds:02d}s (DONE) | "
            f"Total Files Processed: {total_files}"
        )
        
        main_progress_label.config(text=f"Progress in <{os.path.basename(ROOT_DIRECTORY)}>: {current_dir_count}/{total_dirs} directories")
        current_file_label.config(text="All files complete: 100% (Ready to close)")
        timer_label.config(text=final_stat_str) # Use the new combined string
        calculate_etr()
        
        # Ensure bars are full
        main_progress_bar['value'] = total_dirs
        sub_progress_bar['value'] = current_dir_max_files
        
        print("Extraction completed!")

def start_extraction():
    # Handles the button click, prepares data, and switches the UI

    global ROOT_DIRECTORY, start_time, total_dirs, total_files, last_update_time, all_files_to_process
    
    if not os.path.isdir(ROOT_DIRECTORY):
        messagebox.showerror("Error", f"Invalid directory: {ROOT_DIRECTORY}. Please check the DEFAULT_ROOT_DIRECTORY constant.")
        # Quit application if the directory is invalid
        window.destroy()
        return

    try:
        # 1. Pre-scan the directory
        total_dirs, total_files, all_files_to_process = preprocess_dir(ROOT_DIRECTORY)
        
        # If no files or directories are found (handled in prepare_workflow)
        if total_dirs == 0 and total_files == 0:
            cancel_extraction()
            return
            
        # 2. Build and show the progress UI
        setup_progress_ui()
        
        # 3. Initialize time and start the recursive loop
        start_time = time.time()
        last_update_time = time.time() # Initialize last update time
        window.after(100, update_gui)
        
    except FileNotFoundError as e:
        messagebox.showerror("Error", str(e))
        window.destroy()

def setup_progress_ui():
    """Builds the labels and bars for the progress display."""
    global title, main_progress_label, current_file_label, timer_label, main_progress_bar, sub_progress_bar, cwd_label, etr_label
    
    # Set window size for progress view (Increased height to 280 for the new label)
    window.geometry("450x280") 
    
    # Title Label 
    title = ttk.Label(window, text="Extracting Features from APK Files", font=('Helvetica', 14, 'bold'))
    title.pack(pady=(15, 5))

    # Folder Progress Bar 
    root_folder_name = os.path.basename(ROOT_DIRECTORY)
    main_progress_label = ttk.Label(window, text=f"Progress in <{root_folder_name}>: 0/{total_dirs} directories", font=('Helvetica', 10))
    main_progress_label.pack(pady=(10, 2))
    
    main_progress_bar = ttk.Progressbar(window, orient="horizontal", length=400, mode="determinate")
    main_progress_bar.pack(pady=5)
    main_progress_bar['maximum'] = total_dirs
    main_progress_bar['value'] = 0

    # Current Folder Label 
    cwd_label = ttk.Label(window, text="Current Folder: Starting...", font=('Helvetica', 10))
    cwd_label.pack(pady=(5, 2)) 
    
    # Sub-Task Progress Bar 
    sub_progress_bar = ttk.Progressbar(window, orient="horizontal", length=400, mode="determinate")
    sub_progress_bar.pack(pady=5)
    sub_progress_bar['maximum'] = 1 
    sub_progress_bar['value'] = 0

    # Current Task Label 
    current_file_label = ttk.Label(window, text="Current Task: Waiting for initialization...", font=('Helvetica', 10, 'italic'))
    current_file_label.pack(pady=(5, 2))
    
    # Timer/Files Label 
    timer_label = ttk.Label(window, text="Time: 00:00:00 | Files Processed: 0/0", font=('Helvetica', 10, 'italic'))
    timer_label.pack(pady=10)

    # Estimated Time Remaining Label 
    etr_label = ttk.Label(window, text="Approximate Time Remaining: Calculating...", font=('Helvetica', 10, 'bold'))
    etr_label.pack(pady=5)

def cancel_extraction():
    window.geometry("450x100")
    ttk.Label(window, text="Extraction Canceled: Directory is Empty.", font=('Helvetica', 14, 'bold')).pack(pady=20)
    
def create_window():
    # Initializes window and starts extracting
    global window

    window = tk.Tk()
    window.title("Feature Extraction")
    # Initial size, resized in setup_progress_ui
    window.geometry("450x50") 
    
    # Center window on screen
    x = (window.winfo_screenwidth() / 2) - (450 / 2)
    y = (window.winfo_screenheight() / 2) - (50 / 2)
    window.geometry(f"+{int(x)}+{int(y)}")

if __name__ == "__main__":
    create_window()

    # Start the extraction after window is fully initialized
    window.after(10, start_extraction())
    window.mainloop()
