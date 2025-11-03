"""
Directory & File Buster
A multi-threaded script to discover hidden files and directories on a web server.

This tool is for educational purposes and for authorized security testing only.
Running this script against websites without explicit permission from the owner
is illegal and unethical. The author assumes no liability for misuse.

Test legally on
http://testphp.vulnweb.com
http://testasp.vulnweb.com

options:
-u : url
-w : wordlist
-t : threads
-d : debug

"""

import requests
import argparse
import threading
import queue
import json
import sys
import time
from urllib.parse import urlparse, urljoin

work_queue = queue.Queue()
results = []
results_lock = threading.Lock()
DEBUG_MODE = False

def vprint(text):
    """Verbose print. Only prints if DEBUG_MODE is True."""
    if DEBUG_MODE:
        print(text, file=sys.stderr)

def test_path(base_url):
    """
    Worker function that pulls paths from the queue and tests them.
    """
    while not work_queue.empty():
        try:
            path = work_queue.get_nowait()
            path = path.strip()
            if not path:
                continue

            target_url = urljoin(base_url, path)

            vprint(f"[Debug] Testing: {target_url}")

            try:
                response = requests.get(target_url, allow_redirects=False, timeout=5, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                })

                if response.status_code != 404:
                    result_data = {
                        "url": target_url,
                        "status_code": response.status_code,
                        "content_length": len(response.content)
                    }
                    with results_lock:
                        results.append(result_data)
                        vprint(f"[+] Found: {target_url} (Status: {response.status_code})")

            except requests.exceptions.RequestException as e:
                vprint(f"[!] Error testing {target_url}: {e}")

        except queue.Empty:
            break
        finally:
            work_queue.task_done()

def main():
    global DEBUG_MODE

    parser = argparse.ArgumentParser(description="Directory & File Buster")
    parser.add_argument("-u", "--url",
                        help="Target URL (e.g., http://example.com/)",
                        required=True)
    parser.add_argument("-w", "--wordlist",
                        help="Path to the wordlist file",
                        required=True)
    parser.add_argument("-t", "--threads",
                        help="Number of threads to use",
                        type=int,
                        default=10)
    parser.add_argument("-d", "--debug",
                        help="Enable debug mode (prints verbose output to stderr)",
                        action="store_true")

    args = parser.parse_args()

    if args.debug:
        DEBUG_MODE = True
        vprint("[Debug] Debug mode enabled.")

    base_url = args.url
    if not base_url.endswith('/'):
        base_url += '/'

    vprint(f"[Debug] Base URL set to: {base_url}")
    vprint(f"[Debug] Loading wordlist from: {args.wordlist}")

    try:
        with open(args.wordlist, 'r') as f:
            for line in f:
                work_queue.put(line.strip())
        vprint(f"[Debug] Loaded {work_queue.qsize()} paths into the queue.")
        if work_queue.empty():
            print("Error: Wordlist is empty.", file=sys.stderr)
            sys.exit(1)
            
    except FileNotFoundError:
        print(f"Error: Wordlist file not found at '{args.wordlist}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading wordlist file: {e}", file=sys.stderr)
        sys.exit(1)

    start_time = time.time()
    vprint(f"[Debug] Starting {args.threads} worker threads...")

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=test_path, args=(base_url,))
        t.start()
        threads.append(t)

    work_queue.join()

    for t in threads:
        t.join()

    vprint(f"[Debug] All threads finished. Total time: {time.time() - start_time:.2f}s")

    if DEBUG_MODE:
        vprint(f"[Debug] Total findings: {len(results)}")
        vprint("--- Scan Complete ---")

    if not DEBUG_MODE:
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
