import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
import time
import os
import FeatureExtractor #Logic for extracting features

# --- Configuration ---
# NOTE: Set the absolute path to your desired root directory here.
DEFAULT_ROOT_DIRECTORY = r'..\Datasets\amd_data'
DEFAULT_ROOT_DIRECTORY_NAME = 
UPDATE_INTERVAL_MS = 50 # GUI update rate (Simulated processing time per file)

# --- State Variables ---
start_time = 0
# State trackers for the two bars
total_dirs = 0
total_files_in_workflow = 0
current_dir_count = 0 
current_file_count = 0
current_dir_max_files = 0
# NEW: Total files processed across all directories
total_files_processed = 0 
# NEW: List to track individual file processing times (for ETC calculation)
file_process_times = []
# NEW: Timestamp of the last successful file process completion
last_update_time = 0

# UI References
task_title_label = None
folder_progress_label = None
subtask_progress_label = None 
timer_label = None
# NEW: Estimated Time Remaining Label
etc_label = None
root_window = None
main_progress_bar = None # Renamed from folder_bar for clarity
sub_progress_bar = None # FIX: Added global declaration for sub_progress_bar
cwd_label = None 
total_files_label = None 

# Workflow data
workflow_iterator = None
current_dir_path = ""
current_file_list = []
ROOT_DIRECTORY_PATH = ""
ALL_FILES_TO_PROCESS = [] # MUST be defined globally and populated in prepare_workflow


# --- Core Logic Functions ---

def prepare_workflow(root_path):
    """
    Scans the root path to pre-calculate the total number of directories and files 
    that need to be processed. This is essential for accurate progress bars.
    """
    global total_dirs, total_files_in_workflow, ALL_FILES_TO_PROCESS # ADDED ALL_FILES_TO_PROCESS to global scope
    
    dir_count = 0
    file_count = 0
    
    # Store the actual os.walk data to iterate over later
    workflow_data = [] # Temporary list
    ALL_FILES_TO_PROCESS = [] # Ensure global list is clean
    
    # Perform a quick scan to get all counts
    for dirpath, dirnames, filenames in os.walk(root_path):
        dir_count += len(dirnames) # Count subdirectories
        # Only count files that are *not* directories themselves in the current view
        valid_filenames = [f for f in filenames if f.lower().endswith('.apk')]
        file_count += len(valid_filenames)
        if valid_filenames or not dirnames: # Add the entry if it contains files or is an empty directory
            workflow_data.append((dirpath, valid_filenames))

    # The total number of steps in the first bar is the number of directories visited.
    total_dirs = len(workflow_data) 
    total_files_in_workflow = file_count
    
    # CRITICAL FIX: Assign the data to the global list for update_gui to read later
    ALL_FILES_TO_PROCESS = workflow_data
    
    if total_dirs == 0:
        # Check if root path has files but no subdirs, still treat as one step
        if not total_files_in_workflow:
            # Handle case where directory is empty
            print(f"Directory {root_path} is empty. Task completed.")
            return 0, 0, iter([])
        
    # We no longer return the iterator because the data is now stored globally in ALL_FILES_TO_PROCESS
    # The return values are kept for compatibility with the function call in start_extraction_workflow.
    return total_dirs, total_files_in_workflow, None 

def calculate_etc():
    """Calculates and updates the Estimated Time Remaining (ETC)."""
    global etc_label

    # Avoid calculation if no files have been processed yet
    if not total_files_processed:
        etc_label.config(text="Approximate Time Remaining: Calculating...")
        return 0 # Return 0 seconds remaining if no files are processed
        
    # 1. Calculate Average Time Per File
    # In this simulated environment, we use the sum of simulated times.
    # In a real environment, this would be the actual time measured for each file.
    total_time_spent_processing = sum(file_process_times)
    average_time_per_file = total_time_spent_processing / total_files_processed
    
    # 2. Calculate Time Remaining
    files_remaining = total_files_in_workflow - total_files_processed
    time_remaining_seconds = files_remaining * average_time_per_file
    
    # 3. Format Output
    
    # Convert remaining time to H:M:S format
    etc_minutes = int(time_remaining_seconds // 60)
    etc_seconds = int(time_remaining_seconds % 60)
    
    etc_label.config(text=f"Approximate Time Remaining: {etc_minutes:02d}m {etc_seconds:02d}s")
    
    return time_remaining_seconds # Return raw seconds for use in update_gui

def update_gui():
    """Recursively drives the processing task and updates the progress bars."""
    global current_dir_count, current_file_count, current_dir_max_files, total_files_processed
    global current_dir_path, current_file_list, workflow_iterator, last_update_time

    if current_dir_count < total_dirs:
        
        # Get current directory path and file list from the globally populated list
        current_dir_path, current_file_list = ALL_FILES_TO_PROCESS[current_dir_count]
        files_in_current_dir = len(current_file_list)
        
        # Check if we are done with files in the current folder
        if current_file_count >= files_in_current_dir:
            # Reset file count and move to next directory
            current_dir_count += 1
            current_file_count = 0
            # Since we moved to the next directory, restart the loop to process its first file
            root_window.after(1, update_gui)
            return

        # --- Sub-Task (File Bar) Iteration ---
        
        # Calculate time taken for the last file *before* simulating the next step
        time_taken_for_file = 0
        if last_update_time: 
            time_taken_for_file = time.time() - last_update_time
            file_process_times.append(time_taken_for_file)
        
        # --- START REAL WORK: APK FEATURE EXTRACTION ---
        
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
        
        # 2. Update tracking counts
        current_file_count += 1
        total_files_processed += 1
        
        # Update timestamp for next calculation
        last_update_time = time.time()

        # 3. Update Labels and Progress Bars
        
        # Main Progress Bar (Folders)
        # Note: current_dir_count is only fully incremented when a folder finishes, 
        # but we use it here as the base value
        main_progress_bar['value'] = current_dir_count
        root_folder_name = os.path.basename(DEFAULT_ROOT_DIRECTORY)
        # FIX: Changed TOTAL_DIRS to total_dirs
        folder_progress_label.config(text=f"Progress in <{root_folder_name}>: {current_dir_count} / {total_dirs} Folders") 

        # Current Folder Name
        cwd_label.config(text=f"Current Folder: {os.path.basename(current_dir_path)}")

        # Sub-Task Progress Label
        subtask_progress_label.config(
            text=f"Current Task: Processing file {current_file_count} / {files_in_current_dir}"
        )

        # Sub-Progress Bar (Files in current folder)
        sub_progress_bar['value'] = current_file_count

        # 4. Update Time and ETC Labels
        elapsed_time = time.time() - start_time
        minutes = int(elapsed_time // 60)
        seconds = int(elapsed_time % 60)
        
        # Live Time Elapsed and Total Files Processed
        timer_label.config(text=f"Time Elapsed: {minutes:02d}m {seconds:02d}s | Total Files Processed: {total_files_processed}")
        
        # Approximate Time Remaining
        calculate_etc() # No longer need to capture return value, calculation updates the label directly
        
        # Schedule the next file to run immediately (without a fixed delay)
        root_window.after(1, update_gui)
        
    else:
        # --- Workflow Completion ---
        
        # Set final values for progress bars
        # FIX: Changed TOTAL_DIRS to total_dirs
        main_progress_bar['value'] = total_dirs
        sub_progress_bar['value'] = 1 # Mark final file as done

        final_time = time.time() - start_time
        final_minutes = int(final_time // 60)
        final_seconds = int(final_time % 60)

        # Update labels to final completion status
        task_title_label.config(text="EXTRACTION COMPLETE!")
        cwd_label.config(text="Current Folder: Done.")
        subtask_progress_label.config(text=f"Current Task: Finished processing {total_files_processed} APK files.")
        etc_label.config(text="Approximate Time Remaining: 00m 00s")
        
        # Final Time Elapsed and Total Files Processed Stat
        timer_label.config(
            text=f"Time Elapsed: {final_minutes:02d}m {final_seconds:02d}s (DONE) | Total Files Processed: {total_files_processed}"
        )
        
        print("Task completed!")
        # Window remains open until closed by user (no root_window.destroy)

def setup_progress_ui(root_window):
    """Configures the labels, bars, and layout for the progress window."""
    global task_title_label, folder_progress_label, timer_label, etc_label, main_progress_bar, sub_progress_bar, cwd_label, subtask_progress_label

    # --- Title Label ---
    task_title_label = ttk.Label(root_window, text="Extracting Features from APK Files", font=('Helvetica', 12, 'bold'))
    task_title_label.pack(pady=(15, 5))

    # --- MAIN PROGRESS BAR (Folders) ---
    root_folder_name = os.path.basename(DEFAULT_ROOT_DIRECTORY)
    # FIX: Changed TOTAL_DIRS to total_dirs
    folder_progress_label = ttk.Label(root_window, text=f"Progress in <{root_folder_name}>: 0/{total_dirs} directories", font=('Helvetica', 10))
    # FIX: Assign folder_progress_label
    folder_progress_label.pack(pady=(10, 2))
    
    # The progressbar widget is created locally
    main_progress_bar_local = ttk.Progressbar(root_window, orient="horizontal", length=400, mode="determinate")
    main_progress_bar_local.pack(pady=5)
    main_progress_bar_local['maximum'] = total_dirs
    main_progress_bar_local['value'] = 0
    # Assign local widget to global reference
    global main_progress_bar
    main_progress_bar = main_progress_bar_local
    
    # --- Current Folder ---
    cwd_label = ttk.Label(root_window, text="Current Folder: Starting...", font=('Helvetica', 10))
    # FIX: Assign cwd_label
    cwd_label.pack(pady=(5, 2)) 
    
    # --- 2. Sub-Task Progress Bar (Second Bar) ---
    # NOTE: The local variable name 'subtask_bar' is created here
    subtask_bar = ttk.Progressbar(root_window, orient="horizontal", length=400, mode="determinate")
    subtask_bar.pack(pady=5)
    subtask_bar['maximum'] = 1 
    subtask_bar['value'] = 0

    # FIX: Assign the local 'subtask_bar' to the global 'sub_progress_bar' reference
    global sub_progress_bar 
    sub_progress_bar = subtask_bar

    # --- MOVED: Current Task Label (Now below the second bar) ---
    subtask_progress_label = ttk.Label(root_window, text="Current Task: Waiting for initialization...", font=('Helvetica', 10, 'italic'))
    # FIX: Assign subtask_progress_label
    subtask_progress_label.pack(pady=(5, 2))
    
    # --- Time & Files Label (Combined for efficiency and space) ---
    timer_label = ttk.Label(root_window, text="Time Elapsed: 00m 00s | Total Files Processed: 0", font=('Helvetica', 10, 'italic'))
    # FIX: Assign timer_label
    timer_label.pack(pady=10)

    # --- NEW: Estimated Time Remaining Label ---
    etc_label = ttk.Label(root_window, text="Approximate Time Remaining: Calculating...", font=('Helvetica', 10, 'bold'))
    # FIX: Assign etc_label
    etc_label.pack(pady=5)

def start_extraction_workflow():
    """Initializes the workflow, prepares data, and starts the GUI update loop."""
    global start_time, BASE_OUTPUT_PATH, last_update_time
    
    # Use the predefined constant
    ROOT_DIRECTORY_PATH = DEFAULT_ROOT_DIRECTORY
    
    if not os.path.isdir(ROOT_DIRECTORY_PATH):
        messagebox.showerror("Error", f"Invalid directory: {ROOT_DIRECTORY_PATH}. Please check the DEFAULT_ROOT_DIRECTORY constant.")
        # Quit application if the directory is invalid
        root_window.destroy()
        return

    try:
        # 1. Pre-scan the directory
        # The third returned value (workflow_iterator) is now None, but the 
        # global ALL_FILES_TO_PROCESS is populated.
        total_dirs, total_files_in_workflow, _ = prepare_workflow(ROOT_DIRECTORY_PATH)
        
        # If no files or directories are found (handled in prepare_workflow)
        if total_dirs == 0 and total_files_in_workflow == 0:
            setup_completion_ui()
            return
            
        # 2. Build and show the progress UI
        # FIX: Added 'root_window' argument to the function call
        setup_progress_ui(root_window)
        
        # 3. Initialize Tracking and Start Loop
        BASE_OUTPUT_PATH = os.path.dirname(os.path.abspath(__file__))
        
        # FIX: Initialize both start_time and last_update_time to ensure time tracking works from the first file.
        start_time = time.time()
        last_update_time = time.time()
        
        # Start the recursive update loop after a small delay
        root_window.after(100, update_gui) 

        
    except FileNotFoundError as e:
        messagebox.showerror("Error", str(e))
        root_window.destroy()

def setup_completion_ui():
    """Simple UI for when the task is skipped (e.g., empty directory)."""
    root_window.geometry("450x100")
    ttk.Label(root_window, text="Task Skipped: Directory is Empty.", font=('Helvetica', 14, 'bold')).pack(pady=20)
    
def create_progress_bar_popup():
    """Initializes the window and automatically starts the workflow."""
    global root_window

    root_window = tk.Tk()
    root_window.title("Feature Extraction Workflow")
    # Initial small size, will resize in setup_progress_ui
    root_window.geometry("450x50") 
    
    # Center the window on the screen
    screen_width = root_window.winfo_screenwidth()
    screen_height = root_window.winfo_screenheight()
    x = (screen_width / 2) - (450 / 2)
    y = (screen_height / 2) - (50 / 2)
    root_window.geometry(f"+{int(x)}+{int(y)}")

    # Automatically start the workflow after the window is fully initialized
    root_window.after(10, start_extraction_workflow)

    root_window.mainloop()

if __name__ == "__main__":
    create_progress_bar_popup()
