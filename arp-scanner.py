"""
    Sends an ARP request to the target IP or range and returns a list
    of devices that responded.
"""

import scapy.all as scapy
import argparse
import requests
import time
import os
import sys
import ctypes

def get_arguments():
    parser = argparse.ArgumentParser(description="An ARP network scanner with manufacturer lookup.")
    parser.add_argument("-t", "--target", 
                        dest="target", 
                        required=True, 
                        help="Target IP address or IP range (e.g., 192.168.1.1/24)")
    options = parser.parse_args()
    return options

def get_vendor(mac_address):
    """
    Queries the macvendors.com API to find the manufacturer
    for a given MAC address.
    """
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.content.decode()
        elif response.status_code == 404:
            return "Unknown / Private"
        else:
            return "API Error"
    except requests.exceptions.RequestException as e:
        return "N/A (Network Error)"

def scan(ip):
    """
    Sends an ARP request to the target IP or range and returns a list
    of devices that responded.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast_frame / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    return answered_list

def print_results(answered_list):
    print("\nScan Results:")
    print("IP Address\t\tMAC Address\t\tManufacturer")
    print("-------------------------------------------------------------------------")
    
    clients_list = []
    for element in answered_list:
        ip_addr = element[1].psrc
        mac_addr = element[1].hwsrc
    
        vendor = get_vendor(mac_addr)
        
        print(f"{ip_addr}\t\t{mac_addr}\t{vendor}")
        clients_list.append({"ip": ip_addr, "mac": mac_addr, "vendor": vendor})
    
        time.sleep(0.5)
        
    return clients_list

def run_as_admin():
    """
    Checks for root/admin privileges. If not present,
    it re-runs the script with elevated privileges.
    """
    try:
        if os.geteuid() != 0:
            os.execvp('sudo', ['sudo', sys.executable] + sys.argv)
            sys.exit(0)
    except Exception as e:
        print(f"[!] Error checking/elevating privileges: {e}")
        print("[!] Please try running this script as root or Administrator manually.")
        sys.exit(1)

if __name__ == "__main__":
    run_as_admin() 
    try:
        options = get_arguments()
        scan_result = scan(options.target)
        print_results(scan_result)
    except KeyboardInterrupt:
        print("\n[-] Scan stopped by user.")
    except PermissionError:
        print("\n[!] Error: Root/Administrator privileges are still required, even after attempting to elevate.")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")