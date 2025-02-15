import hashlib
import json
import os
from tkinter import filedialog
import platform

def get_all_drives():
    """Get a list of all drives on the system (Windows & Linux)."""
    drives = []
    
    if platform.system() == "Windows":
        import string
        from ctypes import windll
        bitmask = windll.kernel32.GetLogicalDrives()
        drives = [f"{letter}:/" for letter in string.ascii_uppercase if bitmask & (1 << (ord(letter) - ord("A")))]
    else:
        # On Linux/macOS, scan root directories
        drives = ["/"]

    return drives

def load_signatures(parent_folder="Hash_DB"):
    """Load malware signatures from hash files (MD5, SHA256, SHA1)"""
    hash_files = {
        "md5": os.path.join(parent_folder, "md5.txt"),
        "sha256": os.path.join(parent_folder, "sha256.txt"),
        "sha1": os.path.join(parent_folder, "sha1.txt"),
    }
    
    signatures = {"md5": set(), "sha256": set(), "sha1": set()}

    for hash_type, file_path in hash_files.items():
        try:
            with open(file_path, "r") as f:
                signatures[hash_type] = {line.strip() for line in f if line.strip()}
        except FileNotFoundError:
            print(f"[X] Warning: {file_path} not found. Skipping...")
        except Exception as e:
            print(f"[X] Error reading {file_path}: {e}")
    
    return signatures

signature = load_signatures()

def calculate_hash(filepath, hash_type="md5"):
    """Calculate the hash of a given file using the specified hash type."""
    try:
        hasher = hashlib.new(hash_type)  # Supports md5, sha256, sha1
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        print(f"[X] File not found: {filepath}")
        return None
    except Exception as e:
        print(f"[X] Error reading file: {e}")
        return None

def check_file(filepath, signatures=signature):
    """Check if a file matches any malware hash signatures."""
    results = {}

    for hash_type in ["md5", "sha256", "sha1"]:
        file_hash = calculate_hash(filepath, hash_type)
        if file_hash:
            if file_hash in signatures[hash_type]:
                print(f"[!] Malware detected ({hash_type.upper()}): {filepath} (Hash: {file_hash})")
                results[hash_type] = True
            else:
                results[hash_type] = False

    return any(results.values())  # Returns True if any hash matches malware signatures

def check_directory(directory, signatures):
    """Scan all files in a directory and its subdirectories."""
    print(f"[*] Scanning: {directory}")
    for root, _, files in os.walk(directory):  # Ignore errors to prevent crashes
        for file in files:
            file_path = os.path.join(root, file)
            check_file(file_path, signatures)

def custom_scan(folder):
    """Let user choose a folder to scan."""
    #  = filedialog.askdirectory(title="Select Folder to Scan")
    if folder:
        print(f"[*] Starting custom scan for: {folder}")
        signatures = load_signatures("hash_db")
        check_directory(folder, signatures)
    else:
        print("[X] No folder selected. Scan cancelled.")

def full_system_scan():
    """Perform a full system scan on all drives."""
    signatures = load_signatures("hash_db")
    drives = get_all_drives()
    
    for drive in drives:
        print(f"[*] Scanning drive: {drive}")
        check_directory(drive, signatures)