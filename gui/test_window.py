import tkinter as tk

def create_test_window():
    # Create the main window
    root = tk.Tk()
    root.title("Test Window")
    root.geometry("400x300")
    
    # Create a basic label
    label = tk.Label(root, text="Test Label", bg="yellow")
    label.pack(pady=20)
    
    # Create a basic button
    button = tk.Button(root, text="Test Button", bg="lightblue")
    button.pack(pady=20)
    
    # Create a basic entry
    entry = tk.Entry(root)
    entry.pack(pady=20)
    
    # Start the main loop
    root.mainloop()

if __name__ == "__main__":
    create_test_window() 