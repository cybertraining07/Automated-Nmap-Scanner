# Automated Nmap Scanner

## Project Overview

Automated Nmap Scanner is a Python-based network security assessment tool designed to automate port scanning, service detection, security finding identification, and report generation.

The project uses Nmap to scan authorized targets and Python to analyze scan results and generate structured security reports in XML, JSON, and HTML formats.

It is designed as a cybersecurity learning project to demonstrate practical skills in network reconnaissance, vulnerability assessment, security analysis, and technical reporting.

## Project Objectives

- Automate TCP port scanning using Nmap.
- Identify open ports and running services.
- Detect selected HTTP security misconfigurations.
- Analyze scan results using Python.
- Assign project-defined risk scores and confidence levels.
- Generate professional security assessment reports.
- Provide remediation recommendations for identified findings.
## Features

- TCP port scanning using Nmap.
- Service and version detection.
- HTTP title and response header inspection.
- Detection of HTTP directory listing.
- Identification of missing HTTP security headers.
- Detection of potentially risky HTTP methods.
- HTTP server information disclosure detection.
- Automated security finding analysis.
- Risk scoring and confidence classification.
- Remediation priority ranking.
- XML scan output.
- JSON security assessment reports.
- HTML security assessment reports.
- Authorization confirmation before scanning.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3 | Scanner automation and analysis |
| Nmap | Network scanning and service detection |
| XML | Structured Nmap scan results |
| JSON | Security findings and scan data |
| HTML | Human-readable assessment reports |
| Kali Linux | Development and testing environment |
| Linux Terminal | Project execution and management |

## Project Structure

```text
Automated-Nmap-Scanner/
├── scanner.py
├── findings.py
├── html_report.py
├── requirements.txt
├── README.md
├── docs/
└── reports/
    ├── XML reports
    ├── JSON reports
    └── HTML reports
```
## Installation and Setup

### Prerequisites

Before installing the project, ensure you have:

- Kali Linux or another compatible Linux distribution.
- Python 3 installed.
- Nmap installed.
- Git installed (optional, for cloning the repository).

### 1. Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd Automated-Nmap-Scanner
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with your actual GitHub repository URL.

### 2. Install Nmap

```bash
sudo apt update
sudo apt install nmap -y
```

### 3. Create a Python Virtual Environment

```bash
python3 -m venv venv
```

### 4. Activate the Virtual Environment

```bash
source venv/bin/activate
```

### 5. Install Python Dependencies

```bash
pip install -r requirements.txt
```
## Usage Instructions

### 1. Navigate to the Project Directory

```bash
cd Automated-Nmap-Scanner
```

### 2. Activate the Virtual Environment

```bash
source venv/bin/activate
```

### 3. Run the Scanner

Example: scan your local test machine on port 8080.

```bash
python3 scanner.py 127.0.0.1 --ports 8080
```

### 4. Confirm Authorization

The scanner requests confirmation before starting.

```text
AUTHORIZED SECURITY TESTING ONLY
Confirm permission to scan 127.0.0.1? (yes/no):
```

Enter `yes` only when you have permission to scan the target.

### 5. Review Generated Reports

After a successful scan, the scanner generates:

- XML report containing Nmap scan data.
- JSON report containing structured scan results and findings.
- HTML report containing security findings and remediation priorities.

Reports are saved in the `reports/` directory.

**Important:** Only scan systems you own or have explicit authorization to test.
## Sample Scan Results

The scanner was tested against a local HTTP test server running on `127.0.0.1` using port `8080`.

### Scan Configuration

| Parameter | Value |
|---|---|
| Target | 127.0.0.1 |
| Port | 8080 |
| Scan Type | TCP Connect Scan |
| Service Detection | Enabled |
| Testing Environment | Kali Linux |
| Target Service | Python SimpleHTTPServer |

### Detected Security Findings

| Finding ID | Finding | Severity |
|---|---|---|
| HTTP-001 | HTTP Directory Listing Enabled | Medium |
| HTTP-004 | Missing HTTP Security Headers | Low |
| HTTP-002 | HTTP Server Information Disclosure | Informational |

### Assessment Summary

- Hosts scanned: 1
- Open ports detected: 1
- Total findings: 3
- Overall risk rating: Medium

### Generated Reports

The assessment produces three report formats:

- XML: Raw Nmap scan information.
- JSON: Structured scan data and security findings.
- HTML: Human-readable security assessment with remediation priorities.

**Note:** The risk scores and overall risk rating are project-defined triage values, not official CVSS scores. Findings should be manually validated before being treated as confirmed vulnerabilities.
## Limitations

The current version of Automated Nmap Scanner has the following limitations:

- Detection is focused on selected HTTP security misconfigurations.
- It does not perform comprehensive web application vulnerability testing.
- Automated findings may require manual verification.
- Risk scores are project-defined and are not official CVSS ratings.
- Scan results depend on target availability and Nmap detection capabilities.
- The scanner currently focuses on TCP port scanning.

## Future Improvements

Potential enhancements for future versions include:

- Add configurable port ranges and scan profiles.
- Expand HTTP security detection rules.
- Integrate CVSS-based vulnerability scoring.
- Add PDF report generation.
- Improve error handling and logging.
- Add support for additional service detection rules.
- Develop a graphical user interface.
- Add unit tests and automated testing.
- Improve report visualization and analytics.

## Legal and Ethical Notice

This project is intended for educational purposes and authorized security assessments only.

Users must obtain explicit permission before scanning any system, network, server, or application they do not own.

The author is not responsible for unauthorized or unlawful use of this tool.

## Author

Cybersecurity learning project focused on network scanning, security assessment automation, Python programming, and technical reporting.
