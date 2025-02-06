import tkinter as tk
from tkinter import messagebox
from scanner import scan_system
from quarantine import quarantine_file, remove_threats
from logs import generate_report
from scheduler import schedule_scan

class AdwareDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Adware Detection System")
        self.root.geometry("500x400")
        
        tk.Label(root, text="Adware Detection and Prevention System", font=("Arial", 14)).pack(pady=10)
        
        self.scan_button = tk.Button(root, text="Scan System", command=self.scan_system)
        self.scan_button.pack(pady=5)
        
        self.quarantine_button = tk.Button(root, text="Quarantine Threats", command=self.quarantine_threats)
        self.quarantine_button.pack(pady=5)
        
        self.remove_button = tk.Button(root, text="Remove Threats", command=self.remove_threats)
        self.remove_button.pack(pady=5)
        
        self.log_button = tk.Button(root, text="Generate Report", command=self.generate_report)
        self.log_button.pack(pady=5)
        
        self.schedule_button = tk.Button(root, text="Schedule Scan", command=self.schedule_scan)
        self.schedule_button.pack(pady=5)
        
    def scan_system(self):
        threats = scan_system()
        messagebox.showinfo("Scan Complete", f"Detected threats: {threats}")
        
    def quarantine_threats(self):
        quarantine_file()
        messagebox.showinfo("Quarantine", "Threats moved to quarantine.")
    
    def remove_threats(self):
        remove_threats()
        messagebox.showinfo("Removal", "Threats removed successfully.")
    
    def generate_report(self):
        generate_report()
        messagebox.showinfo("Report", "Log report generated.")
    
    def schedule_scan(self):
        schedule_scan()
        messagebox.showinfo("Schedule", "Automatic scanning scheduled.")

if __name__ == "__main__":
    root = tk.Tk()
    app = AdwareDetectionApp(root)
    root.mainloop()
