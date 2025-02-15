import os
import shutil

# Define quarantine directory
QUARANTINE_DIR = "C:\\Quarantine"

# Ensure quarantine directory exists
os.makedirs(QUARANTINE_DIR, exist_ok=True)

def quarantine_file(filepath):
    try:
        if os.path.exists(filepath):
            # Rename file to prevent execution
            filename = os.path.basename(filepath)
            quarantined_name = filename + ".quarantine"
            quarantined_path = os.path.join(QUARANTINE_DIR, quarantined_name)

            # Move file to quarantine
            shutil.move(filepath, quarantined_path)

            # Restrict permissions (Windows-specific)
            os.chmod(quarantined_path, 0o400)  # Read-only for safety

            print(f"[✔] Quarantined: {quarantined_path}")
            return quarantined_path
        else:
            print(f"[!] File not found: {filepath}")
    except Exception as e:
        print(f"[X] Error quarantining file: {str(e)}")

# Example usage: Quarantine a detected adware file
detected_file = "C:\\Users\\User\\Downloads\\adware.exe"
quarantine_file(detected_file)
