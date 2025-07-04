import yara
import multiprocessing
import os

def scan_file_yara(args):
    filepath, rules = args
    try:
        matches = rules.match(filepath)
        if matches:
            return filepath
        return None
    except Exception as e:
        print(f"[!] YARA scan error on {filepath}: {e}")
        return None

def scan_with_yara(file_list, rules_path, processes=4):
    print(f"[*] Loading YARA rules from: {rules_path}")
    try:
        rules = yara.compile(filepath=rules_path)
    except Exception as e:
        print(f"[!] Error compiling YARA rules: {e}")
        return []

    print(f"[*] Scanning {len(file_list)} files with YARA using {processes} processes...")
    with multiprocessing.Pool(processes=processes) as pool:
        results = pool.map(scan_file_yara, [(f, rules) for f in file_list])

    matches = [f for f in results if f]
    print(f"[*] YARA detected {len(matches)} suspicious file(s).")
    return matches
