"""
Automated Reconnaissance Scanner
This script runs an Nmap scan on a target, parses the XML output,
and generates a human-readable report.
"""

import os
import subprocess
import sys
import argparse
import xml.etree.ElementTree as ET

def run_nmap_scan(target_ip, output_xml):

    print(f"[+] Starting Nmap scan for: {target_ip}")

    # -sV: Probe open ports to determine service/version info
    nmap_command = ["nmap", "-sV", "-oX", output_xml, target_ip]

    try:
        result = subprocess.run(
            nmap_command,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        print("[+] Nmap scan completed successfully.")
        return True
    except FileNotFoundError:
        print("[!] Error: 'nmap' command not found.")
        print("[!] Please ensure Nmap is installed and in your system's PATH.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running Nmap: {e}")
        print(f"[!] Stderr: {e.stderr}")
        return False
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        return False
    

def parse_nmap_xml(xml_file):

    print(f"[+] Parsing Nmap XML file: {xml_file}")

    report_lines = []
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        host = root.find("host")
        if host is None:
            print("[!] No host information found in the XML file.")
            # Check if Nmap reported the host as down
            runstats = root.find("runstats")
            if runstats is not None and runstats.find("hosts").get("down") == "1":
                report_lines.append("Host appears to be down.")
            return report_lines

        # Get host address
        address_elem = host.find("address")
        if address_elem is not None:
            address = address_elem.get("addr")
            report_lines.append(f"# Scan Report for: {address}\n")
        else:
            report_lines.append("# Scan Report\n")

        # Find all ports
        ports = host.find("ports")
        if ports is None:
            report_lines.append("No port information found for this host.")
            return report_lines

        open_ports = 0
        for port in ports.findall("port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                open_ports += 1
                portid = port.get("portid")
                protocol = port.get("protocol")
                
                service = port.find("service")
                if service is not None:
                    name = service.get("name", "unknown")
                    product = service.get("product", "unknown")
                    version = service.get("version", "unknown")
                    report_lines.append(f"## Port {portid}/{protocol} (Open)")
                    report_lines.append(f"* **Service:** {name}")
                    report_lines.append(f"* **Product:** {product}")
                    report_lines.append(f"* **Version:** {version}")
                    report_lines.append("")
                else:
                    report_lines.append(f"## Port {portid}/{protocol} (Open)")
                    report_lines.append(f"* Service: unknown")
                    report_lines.append("")

        if open_ports == 0:
            report_lines.append("No open ports found on this host.")

        return report_lines

    except ET.ParseError as e:
        print(f"[!] Error parsing XML file: {e}")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred during parsing: {e}")
        return None

def save_report(report_lines, output_md):

    print(f"[+] Saving report to: {output_md}")

    try:
        with open(output_md, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
        print(f"[+] Successfully saved report to {output_md}")
    except IOError as e:
        print(f"[!] Error saving report file: {e}")

def main():
    
    parser = argparse.ArgumentParser(
        description="Automated Nmap Reconnaissance Scanner.",
        epilog="Example: scanner.py scanme.nmap.org"
    )
    parser.add_argument(
        "target",
        help="The target IP or hostname to scan."
    )
    parser.add_argument(
        "-o", "--output",
        help="Base name for output files (e.g., 'my_scan'). "
             "Defaults to the target name."
    )
    args = parser.parse_args()

    target = args.target
    
    if args.output:
        base_name = args.output
    else:
        base_name = target

    output_xml = f"{base_name}_scan.xml"
    output_md = f"{base_name}_report.md"
    
    print(f"[i] Scan Mode: Target is '{target}'.")
    if not run_nmap_scan(target, output_xml):
        sys.exit(1)

    xml_to_parse = output_xml
    
    if xml_to_parse:
        report_data = parse_nmap_xml(xml_to_parse)
        
        if report_data:
            print("\n" + "="*30)
            print("     Scan Summary Report     ")
            print("="*30 + "\n")
            
            for line in report_data:
                if line.startswith("# "):
                    print(line.replace("# ", "").upper())
                elif line.startswith("## "):
                    print(f"\n--- {line.replace('## ', '')} ---")
                elif line.startswith("* "):
                    print(line.replace("* ", "  "))
                else:
                    print(line)
    
            save_report(report_data, output_md)
        else:
            print("[!] Failed to generate report.")
            
    if os.path.exists(output_xml):
        print(f"[+] Cleaning up intermediate file: {output_xml}")
        os.remove(output_xml)

if __name__ == "__main__":
    main()




