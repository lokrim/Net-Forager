"""
Sends an ARP request to the target IP or range and returns a list
of devices that responded.

syntax : python arp-scanner -d -t <target-network-ip-withmask>

"""

import scapy.all as scapy
import argparse
import requests
import time
import os
import sys
import json


def get_arguments():
    parser = argparse.ArgumentParser(description="An ARP network scanner with manufacturer lookup.")
    parser.add_argument(
        "-t", "--target",
        dest="target",
        required=True,
        help="Target IP address or IP range (e.g., 192.168.1.1/24)"
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Print a tabular summary to stderr in addition to JSON."
    )
    return parser.parse_args()


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
    except requests.exceptions.RequestException:
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


def build_clients(answered_list):
    """
    Build a list of discovered clients with vendor info.
    """
    clients_list = []
    for element in answered_list:
        ip_addr = element[1].psrc
        mac_addr = element[1].hwsrc
        vendor = get_vendor(mac_addr)
        clients_list.append({"ip": ip_addr, "mac": mac_addr, "vendor": vendor})
    return clients_list


def format_table(headers, rows):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    def fmt_row(row):
        return "  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row))
    sep = "  ".join("-" * w for w in widths)
    lines = [fmt_row(headers), sep]
    for row in rows:
        lines.append(fmt_row(row))
    return "\n".join(lines)


def print_debug_table(payload):
    print("\nARP Scan Summary (debug)\n========================", file=sys.stderr)
    print(f"Target : {payload.get('target','')}", file=sys.stderr)
    print(f"Found  : {payload.get('count',0)} device(s)\n", file=sys.stderr)

    devices = payload.get("devices", [])
    if not devices:
        print("No devices found.", file=sys.stderr)
        return

    headers = ["IP Address", "MAC Address", "Manufacturer"]
    rows = [[d.get("ip",""), d.get("mac",""), d.get("vendor","")] for d in devices]
    print(format_table(headers, rows), file=sys.stderr)
    print("", file=sys.stderr)


def run_as_admin(target_for_error=None):
    """
    Checks for root/admin privileges. If not present,
    it re-runs the script with elevated privileges.
    """
    try:
        if os.geteuid() != 0:
            os.execvp('sudo', ['sudo', sys.executable] + sys.argv)
            sys.exit(0)
    except Exception as e:
        error_payload = {
            "target": target_for_error,
            "error": f"Privilege elevation failed: {e}"
        }
        print(json.dumps(error_payload, indent=2))
        print("[!] Please try running this script as root or with sudo.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        options = get_arguments()
        run_as_admin(target_for_error=options.target)

        answered = scan(options.target)
        devices = build_clients(answered)

        payload = {
            "target": options.target,
            "count": len(devices),
            "devices": devices,
            "timestamp": int(time.time())
        }

        if options.debug:
            print_debug_table(payload)
        else:
            print(json.dumps(payload, indent=2))

    except KeyboardInterrupt:
        error_payload = {"error": "Scan stopped by user."}
        print(json.dumps(error_payload, indent=2))
        sys.exit(1)
    except PermissionError:
        error_payload = {
            "target": options.target if 'options' in locals() else None,
            "error": "Root/Administrator privileges are required."
        }
        print(json.dumps(error_payload, indent=2))
        sys.exit(1)
    except Exception as e:
        error_payload = {
            "target": options.target if 'options' in locals() else None,
            "error": f"Unexpected error: {e}"
        }
        print(json.dumps(error_payload, indent=2))
        sys.exit(1)