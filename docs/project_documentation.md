# Automated Nmap Scanner – Technical Documentation

## 1. Project Description

Automated Nmap Scanner is a Python-based network security assessment tool that automates TCP port scanning, service detection, HTTP security analysis, and report generation.

The project combines Nmap with Python to identify selected network and HTTP security misconfigurations on authorized targets.

## 2. Project Architecture

The project consists of three main Python modules:

- **scanner.py:** Validates targets, requests authorization, executes Nmap scans, processes XML output, and generates reports.
- **findings.py:** Analyzes scan results and identifies selected HTTP security issues.
- **html_report.py:** Generates readable HTML security assessment reports.

## 3. Detection Rules

| Finding ID | Detection | Severity |
|---|---|---|
| HTTP-001 | HTTP Directory Listing Enabled | Medium |
| HTTP-002 | HTTP Server Information Disclosure | Informational |
| HTTP-003 | Potentially Risky HTTP Methods Enabled | Medium |
| HTTP-004 | Missing HTTP Security Headers | Low |

## 4. Risk Assessment

The tool assigns project-defined risk scores and confidence levels to findings.

These scores support prioritization and are not official CVSS scores.

Findings should be manually validated before being treated as confirmed vulnerabilities.

## 5. Scanning Methodology

1. Validate the target IP address or hostname.
2. Request authorization confirmation.
3. Execute an Nmap TCP connect scan.
4. Detect available services and versions.
5. Collect HTTP information using selected Nmap scripts.
6. Parse the Nmap XML output.
7. Analyze the results using Python detection rules.
8. Generate XML, JSON, and HTML reports.

## 6. Testing Environment

- Operating system: Kali Linux
- Programming language: Python 3
- Network scanner: Nmap
- Test target: Local HTTP server at 127.0.0.1
- Test port: 8080
- Test service: Python SimpleHTTPServer

## 7. Report Formats

- **XML:** Raw Nmap scan information.
- **JSON:** Structured scan results and security findings.
- **HTML:** Human-readable security findings, risk summaries, and remediation priorities.

## 8. Security Recommendations

- Disable unnecessary directory listing.
- Avoid exposing unnecessary server version information.
- Disable risky HTTP methods when not required.
- Configure appropriate HTTP security headers.
- Review and validate findings before remediation.

## 9. Project Limitations

This tool focuses on selected HTTP security misconfigurations. It does not replace a comprehensive vulnerability scanner or manual penetration test.

## 10. Ethical and Legal Considerations

Only scan systems owned by the user or systems for which explicit authorization has been granted.

This project is intended for educational purposes and authorized security assessments.
