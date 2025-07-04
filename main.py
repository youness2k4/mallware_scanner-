import os
import subprocess
import time
import yara
from tqdm import tqdm

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
                result = subprocess.run(
                    ["clamscan", "--no-summary", filepath],
                    capture_output=True, text=True, timeout=300
                )
                if "FOUND" in result.stdout:
                    infected_files.append(filepath)
                    print(f"[!] Infected file: {filepath}")
                elif result.returncode != 0:
                    print(f"[!] ClamAV error on {filepath}: {result.stderr.strip()}")
            except subprocess.TimeoutExpired:
                print(f"[!] ClamAV scan timed out for {filepath}")
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

def scan_with_yara(file_list, yara_rules_path):
    print(f"[*] Loading YARA rules from: {yara_rules_path}")
    try:
        rules = yara.compile(filepath=yara_rules_path)
    except Exception as e:
        print(f"[!] Error compiling YARA rules: {e}")
        return []

    print(f"[*] Scanning {len(file_list)} files with YARA...")
    matches_found = []

    for filepath in file_list:
        try:
            matches = rules.match(filepath)
            if matches:
                print(f"[YARA] MATCH in {filepath}: {[m.rule for m in matches]}")
                matches_found.append((filepath, [m.rule for m in matches]))
        except Exception as e:
            print(f"[!] YARA scan error on {filepath}: {e}")

    if not matches_found:
        print("[YARA] No matches found.")
    else:
        print(f"[*] YARA found {len(matches_found)} file(s) with matches.")

    return matches_found

if __name__ == "__main__":
    print("Choose scan mode:")
    print("1 - Scan a specific file")
    print("2 - Scan a directory")
    print("3 - Scan the entire computer (may take long and need permissions)")

    while True:
        scan_mode = input("Enter 1, 2, or 3: ")
        if scan_mode in ["1", "2", "3"]:
            break

    target_path = ""
    while True:
        if scan_mode == "1":
            target_path = input("Enter full path of the file to scan: ").strip()
            if os.path.isfile(target_path):
                break
            print("[!] File does not exist. Try again.")

        elif scan_mode == "2":
            target_path = input("Enter full path of the directory to scan: ").strip()
            if os.path.isdir(target_path):
                break
            print("[!] Directory does not exist. Try again.")

        elif scan_mode == "3":
            target_path = "C:/"
            break

    # Run ClamAV Scan
    clamav_infected = scan_with_clamav(target_path)

    # Prepare files for YARA
    yara_files = []
    if os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                yara_files.append(os.path.join(root, file))
    else:
        yara_files = [target_path]

    # Run YARA Scan
    yara_matches = scan_with_yara(yara_files, os.path.join('rules', 'malware_rules.yar'))
