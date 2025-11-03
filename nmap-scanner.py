"""
Automated Reconnaissance Scanner
Runs a customizable Nmap scan on a target, parses the XML output,
and prints a JSON summary to stdout.
In debug mode (-d/--debug), prints a human-readable table to stderr.
"""

import subprocess
import os
import sys
import argparse
import xml.etree.ElementTree as ET
import json


def dprint(debug, msg):
    if debug:
        print(msg, file=sys.stderr)


def run_nmap_scan(target_ip, output_xml, args):
    debug = getattr(args, "debug", False)

    nmap_command = ["nmap", "-sV", "-oX", output_xml]

    needs_sudo = False
    if args.syn_scan:
        nmap_command.append("-sS")
        needs_sudo = True

    if args.os_detect:
        nmap_command.append("-O")
        needs_sudo = True

    if args.ports:
        nmap_command.extend(["-p", args.ports])

    if args.timing is not None:
        nmap_command.extend(["-T", str(args.timing)])

    nmap_command.append(target_ip)

    if needs_sudo and (not nmap_command[0].startswith("sudo")):
        nmap_command = ["sudo"] + nmap_command

    dprint(debug, f"[debug] Executing: {' '.join(nmap_command)}")
    try:
        completed = subprocess.run(
            nmap_command,
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8"
        )
        dprint(debug, "[debug] Nmap stdout:")
        if debug and completed.stdout:
            print(completed.stdout, file=sys.stderr)
        dprint(debug, "[debug] Nmap stderr:")
        if debug and completed.stderr:
            print(completed.stderr, file=sys.stderr)
        return True
    except FileNotFoundError:
        print("Error: 'nmap' command not found. Install Nmap and ensure it's in PATH.", file=sys.stderr)
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error running Nmap: {e}", file=sys.stderr)
        if e.stderr:
            print(e.stderr, file=sys.stderr)
        if "requires root privileges" in (e.stderr or ""):
            print("Hint: Try running the script with 'sudo' for -sS or -O scans.", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Unexpected error during Nmap execution: {e}", file=sys.stderr)
        return False


def parse_nmap_xml(xml_file, debug=False):
    """
    Parse Nmap XML and return a Python dict ready for JSON serialization.
    """
    result = {
        "address": None,
        "host_status": "unknown",
        "os": None,
        "open_ports": []
    }

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        host = root.find("host")
        if host is None:
            runstats = root.find("runstats")
            if runstats is not None:
                hosts = runstats.find("hosts")
                if hosts is not None:
                    up = hosts.get("up")
                    down = hosts.get("down")
                    if down and down.isdigit() and int(down) >= 1 and (not up or int(up) == 0):
                        result["host_status"] = "down"
            return result

        # Host status
        status_elem = host.find("status")
        if status_elem is not None and status_elem.get("state"):
            result["host_status"] = status_elem.get("state")

        # Address
        address_elem = host.find("address")
        if address_elem is not None:
            result["address"] = address_elem.get("addr")

        # OS detection (best match only)
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                name = osmatch.get("name")
                accuracy = osmatch.get("accuracy")
                os_info = {}
                if name:
                    os_info["name"] = name
                if accuracy and accuracy.isdigit():
                    os_info["accuracy"] = int(accuracy)
                if os_info:
                    result["os"] = os_info

        # Ports (only open)
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_info = {
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "state": state.get("state")
                }

                service_elem = port.find("service")
                if service_elem is not None:
                    service_info = {}
                    for key in ["name", "product", "version", "extrainfo", "tunnel"]:
                        val = service_elem.get(key)
                        if val:
                            service_info[key] = val
                    if service_info:
                        port_info["service"] = service_info

                result["open_ports"].append(port_info)

        return result

    except ET.ParseError as e:
        print(f"XML parse error: {e}", file=sys.stderr)
        return {"error": f"XML parse error: {e}"}
    except Exception as e:
        print(f"Unexpected parse error: {e}", file=sys.stderr)
        return {"error": f"Unexpected parse error: {e}"}


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
    # High-level summary
    target = payload.get("target", "")
    address = payload.get("address") or ""
    host_status = payload.get("host_status") or ""
    os_info = payload.get("os") or {}
    os_name = os_info.get("name", "")
    os_acc = os_info.get("accuracy", "")

    print(f"\nNmap Scan Summary (debug)\n=========================", file=sys.stderr)
    print(f"Target      : {target}", file=sys.stderr)
    print(f"Address     : {address}", file=sys.stderr)
    print(f"Host Status : {host_status}", file=sys.stderr)
    if os_name or os_acc != "":
        acc_str = f" ({os_acc}%)" if os_acc != "" else ""
        print(f"OS          : {os_name}{acc_str}", file=sys.stderr)

    # Open ports table
    ports = payload.get("open_ports", []) or []
    print("\nOpen Ports:", file=sys.stderr)
    if not ports:
        print("  None", file=sys.stderr)
        return

    headers = ["PORT", "PROTO", "STATE", "SERVICE", "PRODUCT", "VERSION"]
    rows = []
    for p in ports:
        svc = p.get("service", {}) or {}
        rows.append([
            p.get("port", ""),
            p.get("protocol", ""),
            p.get("state", ""),
            svc.get("name", ""),
            svc.get("product", ""),
            svc.get("version", "")
        ])
    table = format_table(headers, rows)
    print(table, file=sys.stderr)
    print("", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Automated Nmap Reconnaissance Scanner.",
        epilog="Example: sudo python3 nmap-scanner.py -sS -O -T4 -p 1-1000 scanme.nmap.org"
    )
    parser.add_argument("target", help="The target IP or hostname to scan.")
    parser.add_argument(
        "-o", "--output",
        help="Base name for the temporary XML output (e.g., 'my_scan'). Defaults to the target name."
    )
    parser.add_argument("-sS", "--syn-scan", action="store_true", help="Run a faster SYN scan (often requires root).")
    parser.add_argument("-O", "--os-detect", action="store_true", help="Enable OS detection (often requires root).")
    parser.add_argument("-p", "--ports", help="Specify ports to scan (e.g., '80,443', '1-1024').")
    parser.add_argument("-T", "--timing", type=int, choices=range(0, 6), metavar="[0-5]",
                        help="Set Nmap timing template (0=slowest, 5=fastest). Default is 3.")
    parser.add_argument("-d", "--debug", action="store_true", help="Print a tabular debug summary to stderr.")
    args = parser.parse_args()

    target = args.target
    output_xml = "scan.xml"

    if not run_nmap_scan(target, output_xml, args):
        # Emit a JSON error so callers still get machine-readable output
        print(json.dumps({"target": target, "error": "Nmap execution failed"}, indent=2))
        sys.exit(1)

    parsed = parse_nmap_xml(output_xml, debug=args.debug)
    json_payload = {"target": target}
    if isinstance(parsed, dict):
        json_payload.update(parsed)
    else:
        json_payload["error"] = "Failed to parse Nmap XML."

    # Debug table to stderr, JSON to stdout
    if args.debug:
        print_debug_table(json_payload)

    print(json.dumps(json_payload, indent=2))

    if os.path.exists(output_xml):
        try:
            os.remove(output_xml)
        except Exception:
            # Silent cleanup failure
            pass


if __name__ == "__main__":
    main()


