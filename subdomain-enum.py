"""
Subdomain Enumerator
A tool to find subdomains using three methods:
1. Passive (crt.sh)
2. DNS (AXFR Zone Transfer)
3. Active (Wordlist Brute-force)

This tool is for educational purposes and for authorized security testing only.
Running this script against websites without explicit permission from the owner
is illegal and unethical. The author assumes no liability for misuse.

Test legally on
http://testphp.vulnweb.com
http://testasp.vulnweb.com

options:
-d : debug
-w : word list
-t : threads
"""

import argparse
import json
import sys
import socket
import threading
import time
from queue import Queue
import requests
import dns.resolver
import dns.zone
import dns.query

found_subdomains = set()
DEBUG = False
print_lock = threading.Lock()

def print_debug(message):
    """Prints a message to stderr if debug mode is enabled."""
    if DEBUG:
        with print_lock:
            print(f"[{threading.current_thread().name}] {message}", file=sys.stderr)

def query_crtsh(domain):
    """Method 3: Passively finds subdomains using crt.sh."""
    print_debug(f"Starting crt.sh query for {domain}...")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        count = 0
        for entry in data:
            name_value = entry.get('name_value', '')
            names = name_value.split('\n')
            for name in names:
                if name.endswith(f".{domain}") and '*' not in name:
                    if name not in found_subdomains:
                        found_subdomains.add(name)
                        count += 1
                        
        print_debug(f"Found {count} new subdomains via crt.sh.")
        
    except requests.RequestException as e:
        print_debug(f"Error querying crt.sh: {e}")
    except json.JSONDecodeError:
        print_debug("Error decoding JSON from crt.sh.")

def attempt_axfr(domain):
    """Method 2: Attempts a DNS Zone Transfer (AXFR)."""
    print_debug(f"Attempting DNS Zone Transfer (AXFR) for {domain}...")
    
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
    except Exception as e:
        print_debug(f"Could not resolve NS records for {domain}: {e}")
        return

    for ns in ns_records:
        ns_server = str(ns.target)
        print_debug(f"Querying NS: {ns_server}")
        try:
            xfr = dns.query.xfr(ns_server, domain, timeout=5)
            zone = dns.zone.from_xfr(xfr)
            
            if zone:
                print_debug(f"SUCCESS: Zone Transfer successful from {ns_server}!")
                count = 0
                for name in zone.nodes.keys():
                    hostname = f"{name}.{domain}"
                    if hostname not in found_subdomains:
                        found_subdomains.add(hostname)
                        count += 1
                print_debug(f"Found {count} new subdomains via AXFR from {ns_server}.")
                
        except Exception as e:
            print_debug(f"Zone Transfer failed from {ns_server}: {e}")

def brute_force_worker(domain, q):
    """Thread worker for brute-force DNS resolution."""
    while not q.empty():
        sub = q.get()
        hostname = f"{sub.strip()}.{domain}"
        
        try:
            socket.gethostbyname(hostname)
            if hostname not in found_subdomains:
                print_debug(f"Found (Wordlist): {hostname}")
                found_subdomains.add(hostname)
        except socket.error:
            pass
        finally:
            q.task_done()

def brute_force_dns(domain, wordlist_path, threads):
    """Method 1: Manages the multi-threaded wordlist enumeration."""
    print_debug(f"Starting wordlist enumeration with {threads} threads...")
    q = Queue()
    
    try:
        with open(wordlist_path, 'r') as f:
            for line in f:
                if line.strip():
                    q.put(line.strip())
    except FileNotFoundError:
        print_debug(f"Error: Wordlist file not found at {wordlist_path}")
        return
    except Exception as e:
        print_debug(f"Error reading wordlist: {e}")
        return

    if q.empty():
        print_debug("Wordlist is empty.")
        return

    print_debug(f"Loaded {q.qsize()} subdomains into the queue.")

    for i in range(threads):
        t = threading.Thread(
            target=brute_force_worker,
            args=(domain, q),
            name=f"Worker-{i+1}",
            daemon=True
        )
        t.start()
    
    q.join()
    print_debug("Wordlist enumeration finished.")

def main():
    global DEBUG
    
    parser = argparse.ArgumentParser(description="A multi-method subdomain enumeration tool.")
    parser.add_argument("domain", help="The target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to the wordlist file for brute-forcing")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads for brute-forcing (default: 20)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode (prints verbose output to stderr)")
    
    args = parser.parse_args()
    
    if args.debug:
        DEBUG = True

    start_time = time.time()
    print_debug(f"Starting scan for {args.domain}...")

    #Run Enumeration Methods
    crt_thread = threading.Thread(target=query_crtsh, args=(args.domain,), name="crt.sh")
    crt_thread.start()

    axfr_thread = threading.Thread(target=attempt_axfr, args=(args.domain,), name="AXFR")
    axfr_thread.start()

    crt_thread.join()
    axfr_thread.join()

    if args.wordlist:
        brute_force_dns(args.domain, args.wordlist, args.threads)

    end_time = time.time()
    
    output_data = {
        "domain": args.domain,
        "subdomains_found": len(found_subdomains),
        "subdomains": sorted(list(found_subdomains))
    }
    
    if DEBUG:
        print_debug("--- SCRIPT FINISHED ---")
        print_debug(f"Total unique subdomains found: {len(found_subdomains)}")
        print_debug(f"Total time taken: {end_time - start_time:.2f} seconds")
        print(json.dumps(output_data, indent=2))
    else:
        print(json.dumps(output_data, indent=2))

if __name__ == "__main__":
    main()