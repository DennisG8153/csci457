import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
import time
import os
import itertools # Used for chain iteration

# --- State Variables ---
start_time = 0
# State trackers for the two bars
total_dirs = 0
total_files_in_workflow = 0
current_dir_count = 0 
current_file_count = 0
current_dir_max_files = 0
# UI References
task_title_label = None
folder_progress_label = None
subtask_progress_label = None
timer_label = None
root_window = None
folder_bar = None
subtask_bar = None
# Workflow data
workflow_iterator = None
current_dir_path = ""
current_file_list = []
ROOT_DIRECTORY_PATH = ""
UPDATE_INTERVAL_MS = 50 # GUI update rate

# --- Core Logic Functions ---

def prepare_workflow(root_path):
    """
    Pre-scans the directory to calculate totals and prepares the iterator.
    Returns: (Total Directories, Total Files, Walk Iterator)
    """
    global total_dirs, total_files_in_workflow
    
    dir_count = 0
    file_count = 0
    
    # Store the actual os.walk data to iterate over later
    workflow_data = [] 

    # Perform a quick scan to get all counts
    for dirpath, dirnames, filenames in os.walk(root_path):
        dir_count += len(dirnames) # Count subdirectories
        file_count += len(filenames) # Count files
        workflow_data.append((dirpath, filenames))

    # The total number of steps in the first bar is the number of directories visited.
    total_dirs = len(workflow_data) 
    total_files_in_workflow = file_count
    
    if total_dirs == 0:
        raise FileNotFoundError(f"No directories found in {root_path}")
    
    # Return an iterator over the prepared data
    return total_dirs, total_files_in_workflow, iter(workflow_data)

def update_gui():
    """Recursively drives the processing task and updates the progress bars."""
    global current_dir_count, current_file_count, current_dir_max_files
    global current_dir_path, current_file_list, workflow_iterator

    # 1. Timer Update (always runs)
    elapsed_time = time.time() - start_time
    minutes = int(elapsed_time // 60)
    seconds = int(elapsed_time % 60)
    timer_label.config(text=f"Time Elapsed: {minutes:02d}:{seconds:02d}")

    # Check if we are done with all directories
    if current_dir_count < total_dirs:
        
        # --- Sub-Task (File Bar) Iteration ---
        if current_file_count < current_dir_max_files:
            # Simulate processing the next file
            current_file_count += 1
            
            # Update Sub-Task Label (Second Bar)
            file_name = current_file_list[current_file_count - 1] if current_file_list else "Processing folder..."
            subtask_progress_label.config(
                text=f"Current Task: {file_name} ({current_file_count}/{current_dir_max_files} files)"
            )
            subtask_bar['value'] = current_file_count
            
            # Recalculate and update the overall folder bar value
            completed_dirs_value = current_dir_count + (current_file_count / current_dir_max_files if current_dir_max_files else 0)
            folder_bar['value'] = completed_dirs_value
            
            # Schedule the next file step
            root_window.after(UPDATE_INTERVAL_MS, update_gui)
            
        else:
            # --- Folder Iteration: Sub-Task Completed, move to Next Directory ---
            try:
                # Get the next directory from the prepared iterator
                dirpath, filenames = next(workflow_iterator)
                
                # Update global state for the next folder
                current_dir_path = dirpath
                current_file_list = filenames
                current_dir_max_files = len(filenames)
                current_dir_count += 1 # Increment overall directory count
                current_file_count = 0 # Reset file counter for the new directory

                # Set bar maximums
                subtask_bar['maximum'] = current_dir_max_files if current_dir_max_files else 1

                # Update Folder Progress Label (First Bar)
                folder_progress_label.config(
                    text=f"Progress in <{os.path.basename(ROOT_DIRECTORY_PATH)}>: {current_dir_count}/{total_dirs} directories"
                )
                
                # Recursively call update_gui immediately to process the first file in the new directory
                root_window.after(1, update_gui) 
                
            except StopIteration:
                # Iterator is exhausted (should be caught by the outer if, but safe fallback)
                root_window.after(1, update_gui)
    
    else:
        # --- Task Completed ---
        folder_progress_label.config(text=f"Progress in <{os.path.basename(ROOT_DIRECTORY_PATH)}>: {total_dirs}/{total_dirs} directories")
        subtask_progress_label.config(text="All tasks complete: 100% (Ready to close)")
        timer_label.config(text="Time Elapsed: Done.")
        folder_bar['value'] = total_dirs
        subtask_bar['value'] = current_dir_max_files
        print("Workflow completed!")

def start_extraction_workflow(path_entry):
    """Handles the button click, prepares data, and switches the UI."""
    global ROOT_DIRECTORY_PATH, workflow_iterator, start_time, total_dirs, total_files_in_workflow
    
    ROOT_DIRECTORY_PATH = path_entry.get()
    
    if not os.path.isdir(ROOT_DIRECTORY_PATH):
        messagebox.showerror("Error", "Invalid directory selected.")
        return

    try:
        # 1. Pre-scan the directory
        total_dirs, total_files_in_workflow, workflow_iterator = prepare_workflow(ROOT_DIRECTORY_PATH)
        
        # 2. Hide setup elements
        for widget in root_window.winfo_children():
            widget.pack_forget()

        # 3. Build and show the progress UI
        setup_progress_ui()
        
        # 4. Initialize time and start the recursive loop
        start_time = time.time()
        root_window.after(100, update_gui)
        
    except FileNotFoundError as e:
        messagebox.showerror("Error", str(e))
        # Re-show setup UI if needed, but for now, just let user try again.

def select_directory(path_entry):
    """Opens a dialog to select the root directory."""
    directory = filedialog.askdirectory(initialdir="/", title="Select Root Directory")
    if directory:
        path_entry.delete(0, tk.END)
        path_entry.insert(0, directory)

def setup_progress_ui():
    """Builds the labels and bars for the progress display."""
    global task_title_label, folder_progress_label, subtask_progress_label, timer_label, folder_bar, subtask_bar
    
    # --- Title Label ---
    task_title_label = ttk.Label(root_window, text="Extracting Features from APK Files", font=('Helvetica', 14, 'bold'))
    task_title_label.pack(pady=(15, 5))

    # --- 1. Folder Progress Bar (First Bar) ---
    root_folder_name = os.path.basename(ROOT_DIRECTORY_PATH)
    folder_progress_label = ttk.Label(root_window, text=f"Progress in <{root_folder_name}>: 0/{total_dirs} directories", font=('Helvetica', 10))
    folder_progress_label.pack(pady=(10, 2))
    
    folder_bar = ttk.Progressbar(root_window, orient="horizontal", length=400, mode="determinate")
    folder_bar.pack(pady=5)
    folder_bar['maximum'] = total_dirs
    folder_bar['value'] = 0

    # --- 2. Sub-Task Progress Bar (Second Bar) ---
    subtask_progress_label = ttk.Label(root_window, text="Current Task: Waiting for initialization...", font=('Helvetica', 10, 'italic'))
    subtask_progress_label.pack(pady=(5, 2))
    
    subtask_bar = ttk.Progressbar(root_window, orient="horizontal", length=400, mode="determinate")
    subtask_bar.pack(pady=5)
    subtask_bar['maximum'] = 1 
    subtask_bar['value'] = 0

    # --- Timer Label ---
    timer_label = ttk.Label(root_window, text="Time Elapsed: 00:00", font=('Helvetica', 10, 'italic'))
    timer_label.pack(pady=10)


def create_progress_bar_popup():
    """Initializes the window and the directory selection interface."""
    global root_window

    root_window = tk.Tk()
    root_window.title("Feature Extraction Setup")
    root_window.geometry("450x180")
    
    # Center the window on the screen
    screen_width = root_window.winfo_screenwidth()
    screen_height = root_window.winfo_screenheight()
    x = (screen_width / 2) - (450 / 2)
    y = (screen_height / 2) - (180 / 2)
    root_window.geometry(f"+{int(x)}+{int(y)}")

    # --- Setup UI Elements ---
    ttk.Label(root_window, text="Select Root Directory for Feature Extraction:", font=('Helvetica', 12, 'bold')).pack(pady=(15, 5))

    path_entry = ttk.Entry(root_window, width=50)
    path_entry.pack(pady=5, padx=10)
    
    button_frame = ttk.Frame(root_window)
    button_frame.pack(pady=10)
    
    ttk.Button(button_frame, text="Browse", command=lambda: select_directory(path_entry)).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="Start Extraction", command=lambda: start_extraction_workflow(path_entry)).pack(side=tk.LEFT, padx=5)

    root_window.mainloop()

if __name__ == "__main__":
    create_progress_bar_popup()
