import tkinter as tk
from tkinter import scrolledtext, messagebox

class ThreatIntelGUI:
    def __init__(self, root):
        print("Initializing GUI...")
        self.root = root
        self.root.title("Threat Intel Aggregator")
        self.root.geometry("1000x700")
        
        # Set background color
        self.root.configure(bg='white')
        
        print("Setting up UI...")
        self.setup_ui()
        print("UI setup complete")
    
    def setup_ui(self):
        """Set up the main user interface"""
        # Create main container
        main_frame = tk.Frame(self.root, bg='white', padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        print("Creating API selection...")
        # API selection
        api_label = tk.Label(main_frame, text="Select API:", bg='white')
        api_label.pack(pady=(0, 5), anchor='w')
        
        self.api_var = tk.StringVar(value="AbuseIPDB")
        api_menu = tk.OptionMenu(main_frame, self.api_var, "AbuseIPDB", "VirusTotal", "Shodan")
        api_menu.pack(pady=(0, 10), anchor='w')
        
        print("Creating query input...")
        # Query input
        input_frame = tk.Frame(main_frame, bg='white')
        input_frame.pack(fill=tk.X, pady=5)
        
        query_label = tk.Label(input_frame, text="Enter query:", bg='white')
        query_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.query_var = tk.StringVar()
        query_entry = tk.Entry(input_frame, textvariable=self.query_var, width=50)
        query_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        search_btn = tk.Button(input_frame, text="Search", command=self.search)
        search_btn.pack(side=tk.LEFT, padx=(5, 0))
        
        print("Creating results area...")
        # Results area
        self.results_text = scrolledtext.ScrolledText(
            main_frame, 
            wrap=tk.WORD,
            width=80,
            height=30,
            font=('Consolas', 10),
            bg='white'
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.results_text.config(state=tk.DISABLED)
        
        print("Creating status bar...")
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(
            main_frame, 
            textvariable=self.status_var,
            bg='lightgray',
            anchor='w',
            relief=tk.SUNKEN
        )
        status_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Force update the window
        self.root.update()
        print("Window update forced")
    
    def search(self):
        """Handle search button click"""
        query = self.query_var.get().strip()
        api = self.api_var.get()
        
        if not query:
            messagebox.showwarning("Input Error", "Please enter a query")
            return
        
        self.update_status(f"Querying {api} for {query}...")
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.append_result(f"Demo mode: Would query {api} for {query}\n")
        self.results_text.config(state=tk.DISABLED)
        self.update_status("Demo mode - API calls disabled")
    
    def append_result(self, text):
        """Append text to the results area"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)
        self.root.update_idletasks()
    
    def update_status(self, message):
        """Update the status bar"""
        self.status_var.set(message)
        self.root.update_idletasks()

def main():
    """Initialize and run the application"""
    print("Starting application...")
    root = tk.Tk()
    print("Tk instance created")
    app = ThreatIntelGUI(root)
    print("GUI created, starting mainloop")
    root.mainloop()

if __name__ == "__main__":
    main()