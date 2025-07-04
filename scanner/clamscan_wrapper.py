from tqdm import tqdm
import subprocess
import os
import time

def scan_with_clamav(directory):
    infected_files = []
    files_to_scan = []

    # Collect all files
    for root, _, files in os.walk(directory):
        for file in files:
            files_to_scan.append(os.path.join(root, file))

    total_files = len(files_to_scan)
    print(f"[*] Starting ClamAV scan of {total_files} files...")

    start_time = time.time()
    with tqdm(total=total_files, unit="file", desc="ClamAV Scan", ncols=100) as pbar:
        for filepath in files_to_scan:
            try:
                result = subprocess.run(["clamscan", filepath], capture_output=True, text=True)

                if "FOUND" in result.stdout:
                    infected_files.append(filepath)
                    print(f"[!] Infected file: {filepath}")
                elif result.returncode != 0:
                    print(f"[!] ClamAV error on {filepath}: {result.stderr.strip()}")

            except Exception as e:
                print(f"[!] Error scanning {filepath}: {e}")
            pbar.update(1)

    end_time = time.time()
    elapsed = end_time - start_time
    minutes, seconds = divmod(int(elapsed), 60)
    hours, minutes = divmod(minutes, 60)

    print(f"\n[*] ClamAV scan completed in {hours}h {minutes}m {seconds}s.")
    if infected_files:
        print(f"[!] {len(infected_files)} infected files found.")
    else:
        print("[*] No infected files found.")

    return infected_files
