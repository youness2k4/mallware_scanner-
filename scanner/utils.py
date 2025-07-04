import time

def timed_run(func, *args, **kwargs):
    start = time.time()
    result = func(*args, **kwargs)
    end = time.time()
    print(f"[*] {func.__name__} completed in {end - start:.1f} seconds.")
    return result
