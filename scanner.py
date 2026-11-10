
#!/usr/bin/env python3

"""
Automated Nmap Scanner
Version: 1.0
Purpose: Authorized network security assessment.
"""

import argparse
import datetime
import ipaddress
import json
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

from pathlib import Path
from findings import analyze_scan
from html_report import generate_html_report


BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"


def validate_ports(ports):
    """Validate TCP port specifications."""

    import re

    if not re.fullmatch(r"[0-9,-]+", ports):
        raise ValueError("Invalid port format.")

    for item in ports.split(","):
        if not item:
            raise ValueError("Empty port entry.")

        parts = item.split("-")

        if len(parts) > 2:
            raise ValueError("Invalid port range.")

        try:
            numbers = [int(value) for value in parts]
        except ValueError:
            raise ValueError("Ports must be numbers.")

        if any(number < 1 or number > 65535 for number in numbers):
            raise ValueError("Ports must be between 1 and 65535.")

        if len(numbers) == 2 and numbers[0] > numbers[1]:
            raise ValueError("Port range must be ascending.")

    return ports


def validate_target(target):
    """Validate and resolve a single IP or hostname."""

    if not target or "/" in target or any(c.isspace() for c in target):
        raise ValueError("Provide one IP address or hostname.")

    try:
        address = ipaddress.ip_address(target)
        return str(address)

    except ValueError:
        pass

    try:
        result = socket.getaddrinfo(
            target,
            None,
            type=socket.SOCK_STREAM
        )

        if not result:
            raise ValueError("Hostname could not be resolved.")

        return result[0][4][0]

    except socket.gaierror:
        raise ValueError("Invalid or unresolvable target.")


def run_nmap(target, ports):
    """Execute Nmap service detection."""

    import shutil

    if not shutil.which("nmap"):
        raise RuntimeError("Nmap is not installed.")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    xml_file = REPORT_DIR / f"nmap_scan_{timestamp}.xml"

    command = [
        "nmap",
        "-sT",
        "-sV",
        "--version-light",
        "-T3",
        "-Pn",
        "-n",

        "-p", ports,
        "--script", "http-title,http-headers,http-methods",
        "--script-timeout", "30s",
        "-oX", str(xml_file),
        target
    ]

    print("\nStarting Nmap scan...")
    print("Target:", target)
    print("Ports:", ports)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError("Scan exceeded the five-minute timeout.")

    if result.returncode != 0:
        raise RuntimeError(result.stderr or "Nmap execution failed.")

    if not xml_file.exists():
        raise RuntimeError("Nmap XML output was not generated.")

    return xml_file, timestamp


def parse_xml(xml_file):
    """Extract host and service information from Nmap XML."""

    tree = ET.parse(xml_file)
    root = tree.getroot()

    hosts = []

    for host in root.findall("host"):

        status = host.find("status")

        if status is None:
            continue

        if status.get("state") != "up":
            continue

        addresses = [
            address.get("addr")
            for address in host.findall("address")
        ]

        hostnames = [
            name.get("name")
            for name in host.findall("./hostnames/hostname")
        ]

        host_data = {
            "addresses": addresses,
            "hostnames": hostnames,
            "status": status.get("state"),
            "ports": []
        }

        for port in host.findall("./ports/port"):

            state = port.find("state")
            service = port.find("service")

            port_data = {
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "state": state.get("state") if state is not None else "unknown",
                "service": service.get("name") if service is not None else "unknown",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
                "scripts": []
            }

            for script in port.findall("script"):
                port_data["scripts"].append({
                    "id": script.get("id"),
                    "output": script.get("output", "")
                })

            host_data["ports"].append(port_data)

        hosts.append(host_data)

    return hosts



def save_json(hosts, target, timestamp):
    """Save structured scan information and security findings."""

    output_file = REPORT_DIR / f"nmap_scan_{timestamp}.json"

    # Analyze Nmap scan results
    scan_data = {
        "hosts": hosts
    }

    findings = analyze_scan(scan_data)

    # Build complete security report
    report = {
        "project": "Automated Nmap Scanner",
        "target": target,
        "scan_date": datetime.datetime.now().astimezone().isoformat(),
        "scan_type": "TCP Connect and Service Detection",
        "hosts": hosts,
        "findings": findings
    }

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return output_file

    

    

    
        
        
        
        
        
    

         
        

    

def display_results(hosts):
    """Display discovered services in the terminal."""

    print("\n========== SCAN RESULTS ==========")

    if not hosts:
        print("No active hosts found.")
        return

    for host in hosts:

        print("\nHost:", ", ".join(host["addresses"]))
        print("Status:", host["status"])

        if not host["ports"]:
            print("No open ports discovered.")

        for port in host["ports"]:

            if port["state"] == "open":
                print(
                    f'PORT {port["port"]}/{port["protocol"]} | '
                    f'{port["service"]} | '
                    f'{port["product"]} {port["version"]}'
                )


def main():

    parser = argparse.ArgumentParser(
        description="Automated Nmap Network Scanner"
    )

    parser.add_argument(
        "target",
        help="Authorized IP address or hostname"
    )

    parser.add_argument(
        "--ports",
        default="1-1024",
        help="TCP ports, e.g. 22,80,443 or 1-1024"
    )

    args = parser.parse_args()

    try:

        target = validate_target(args.target)
        ports = validate_ports(args.ports)

        print("\nAUTHORIZED SECURITY TESTING ONLY")

        confirmation = input(
            f"Confirm permission to scan {target}? (yes/no): "
        ).strip().lower()

        if confirmation != "yes":
            print("Scan cancelled.")
            return

        xml_file, timestamp = run_nmap(target, ports)

        hosts = parse_xml(xml_file)

        json_file = save_json(hosts, target, timestamp)

        with json_file.open("r", encoding="utf-8") as file:
            report_data = json.load(file)

        html_file = REPORT_DIR / f"nmap_scan_{timestamp}.html"
        generate_html_report(report_data, html_file)

        display_results(hosts)

        print("\n========== REPORT FILES ==========")
        print("XML:", xml_file)
        print("JSON:", json_file)
        print("HTML:", html_file)
        print("\nScan completed successfully.") 


    except (ValueError, RuntimeError, ET.ParseError) as error:

        print("\nERROR:", error)
        sys.exit(1)


if __name__ == "__main__":
    main()
