import os
import hashlib
import json

CACHE_FILE = os.path.join('cache', 'file_hash_cache.json')

def ensure_cache_dir():
    if not os.path.exists('cache'):
        os.makedirs('cache')

def load_cache():
    ensure_cache_dir()
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_cache(cache):
    ensure_cache_dir()
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f)

def calculate_file_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[!] Failed to hash {filepath}: {e}")
        return None

def should_scan(filepath, cache):
    current_hash = calculate_file_hash(filepath)
    if current_hash is None:
        return True  # Can't hash, better scan
    cached_hash = cache.get(filepath)
    if cached_hash == current_hash:
        return False  # No change since last scan
    else:
        cache[filepath] = current_hash
        return True
