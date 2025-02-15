import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ttkthemes import ThemedTk
import realtime_protection 


class AdwareDetectionSystem:
    def __init__(self):
        self.root = ThemedTk(theme="breeze")
        self.root.title("Adware Detection System")
        self.root.geometry("800x600")
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=5)
        
        # Create tabs
        self.scan_tab = ttk.Frame(self.notebook)
        self.protection_tab = ttk.Frame(self.notebook)
        self.quarantine_tab = ttk.Frame(self.notebook)
        self.logs_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.scan_tab, text="Scanner")
        self.notebook.add(self.protection_tab, text="Protection")
        self.notebook.add(self.quarantine_tab, text="Quarantine")
        self.notebook.add(self.logs_tab, text="Logs")
        
        self.setup_scan_tab()
        self.setup_protection_tab()
        self.setup_quarantine_tab()
        self.setup_logs_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_scan_tab(self):
        # Scan options frame
        scan_frame = ttk.LabelFrame(self.scan_tab, text="Scan Options", padding=10)
        scan_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(scan_frame, text="Quick Scan", command=self.quick_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(scan_frame, text="Full System Scan", command=self.full_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(scan_frame, text="Custom Scan", command=self.custom_scan).pack(side=tk.LEFT, padx=5)
        
        # Scan progress
        progress_frame = ttk.LabelFrame(self.scan_tab, text="Scan Progress", padding=10)
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100).pack(fill=tk.X)
        
        # Results frame
        results_frame = ttk.LabelFrame(self.scan_tab, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.results_tree = ttk.Treeview(results_frame, columns=("Type", "Location", "Risk"), show="headings")
        self.results_tree.heading("Type", text="Threat Type")
        self.results_tree.heading("Location", text="Location")
        self.results_tree.heading("Risk", text="Risk Level")
        self.results_tree.pack(fill=tk.BOTH, expand=True)

    def setup_protection_tab(self):
        # Real-time protection settings
        protection_frame = ttk.LabelFrame(self.protection_tab, text="Real-Time Protection", padding=10)
        protection_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Checkbutton(protection_frame, text="Enable Real-time Protection").pack(anchor=tk.W)
        ttk.Checkbutton(protection_frame, text="Automatic Threat Removal").pack(anchor=tk.W)
        ttk.Checkbutton(protection_frame, text="Show Notifications").pack(anchor=tk.W)
        
        # Protection status
        status_frame = ttk.LabelFrame(self.protection_tab, text="Protection Status", padding=10)
        status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.status_text = tk.Text(status_frame, height=10)
        self.status_text.pack(fill=tk.BOTH, expand=True)
        self.status_text.insert(tk.END, "System protected\nLast scan: Never\nThreats detected: 0")

    def setup_quarantine_tab(self):
        quarantine_list_frame = ttk.LabelFrame(self.quarantine_tab, text="Quarantined Items", padding=10)
        quarantine_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.quarantine_tree = ttk.Treeview(quarantine_list_frame, columns=("Date", "Type", "Location"), show="headings")
        self.quarantine_tree.heading("Date", text="Date Quarantined")
        self.quarantine_tree.heading("Type", text="Threat Type")
        self.quarantine_tree.heading("Location", text="Original Location")
        self.quarantine_tree.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(self.quarantine_tab)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(button_frame, text="Delete Selected", command=self.delete_quarantined).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Restore Selected", command=self.restore_quarantined).pack(side=tk.LEFT, padx=5)

    def setup_logs_tab(self):
        logs_frame = ttk.LabelFrame(self.logs_tab, text="System Logs", padding=10)
        logs_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.logs_text = tk.Text(logs_frame)
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(self.logs_tab)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(button_frame, text="Export Logs", command=self.export_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)

    # Event handlers
    def quick_scan(self):
        self.status_var.set("Quick scan in progress...")
        self.progress_var.set(0)
        # Add scan logic here

    def full_scan(self):
        self.status_var.set("Full system scan in progress...")
        self.progress_var.set(0)
        realtime_protection.full_system_scan()
        # Add scan logic here


    def custom_scan(self):
        folder = filedialog.askdirectory()
        if folder:
            self.status_var.set(f"Scanning {folder}...")
            self.progress_var.set(0)
            realtime_protection.custom_scan(folder)
            # Add scan logic here

    def delete_quarantined(self):
        selected = self.quarantine_tree.selection()
        if selected:
            if messagebox.askyesno("Confirm Delete", "Delete selected items permanently?"):
                # Add deletion logic here
                pass

    def restore_quarantined(self):
        selected = self.quarantine_tree.selection()
        if selected:
            if messagebox.askyesno("Confirm Restore", "Restore selected items?"):
                # Add restore logic here
                pass

    def export_logs(self):
        filename = filedialog.asksaveasfilename(defaultextension=".txt")
        if filename:
            # Add export logic here
            pass

    def clear_logs(self):
        if messagebox.askyesno("Confirm Clear", "Clear all logs?"):
            self.logs_text.delete(1.0, tk.END)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = AdwareDetectionSystem()
    app.run()