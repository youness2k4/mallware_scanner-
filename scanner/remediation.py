import os
import shutil

QUARANTINE_DIR = os.path.join('quarantine')

def ensure_quarantine_dir():
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)

def quarantine_file(filepath):
    ensure_quarantine_dir()
    try:
        filename = os.path.basename(filepath)
        dest = os.path.join(QUARANTINE_DIR, filename)
        # If file already exists in quarantine, rename to avoid overwrite
        if os.path.exists(dest):
            base, ext = os.path.splitext(filename)
            count = 1
            while os.path.exists(dest):
                dest = os.path.join(QUARANTINE_DIR, f"{base}_{count}{ext}")
                count += 1
        shutil.move(filepath, dest)
        print(f"[*] Quarantined file: {filepath} -> {dest}")
    except Exception as e:
        print(f"[!] Failed to quarantine {filepath}: {e}")
