import subprocess
import ctypes
import psutil


    
def check_administrtor(): 
    """check the appliction is running as administrator"""
    if ctypes.windll.shell32.IsUserAnAdmin():
        print("Administrtor access granted..")
    else:
        print("Please run the script as Administrator.")

def check_for_rootkits():
    """Runs a basic check for rootkits"""
    print("Checking for rootkits...")
    rootkit_scan = subprocess.run(["sfc", "/scannow"], capture_output=True, text=True)
    print(rootkit_scan.stdout)


def check_running_processes():
    """Lists running processes and checks for suspicious activity"""
    print("Checking running processes...")
    for process in psutil.process_iter(attrs=['pid', 'name']):
        print(f"Process ID: {process.info['pid']}, Name: {process.info['name']}")

