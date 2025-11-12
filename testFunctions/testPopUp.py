import tkinter as tk

def create_progress_bar_popup():
    # Initializes window and starts extracting
    global window

    window = tk.Tk()
    window.title("Feature Extraction Workflow")
    # Initial size, resized in setup_progress_ui
    window.geometry("450x50") 
    
    # Center window on screen
    x = (window.winfo_screenwidth() / 2) - (450 / 2)
    y = (window.winfo_screenheight() / 2) - (50 / 2)
    window.geometry(f"+{int(x)}+{int(y)}")

    # Start the extraction after window is fully initialized
    window.after(5000, print("done"))
    #for i in range(10000):
    #    print(i)

    window.mainloop()

if __name__ == "__main__":
    create_progress_bar_popup()