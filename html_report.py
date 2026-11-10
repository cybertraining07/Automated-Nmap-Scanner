#!/usr/bin/env python3

"""Generate HTML security assessment reports."""

import json
import sys
from html import escape
from pathlib import Path


def generate_html_report(report_data, output_path):
    """Generate a professional HTML report from scan data."""

    hosts = report_data.get("hosts", [])
    findings = report_data.get("findings", [])

    total_hosts = len(hosts)
    total_ports = sum(len(host.get("ports", [])) for host in hosts)


    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0
    }

    for finding in findings:
        severity = finding.get("severity", "Informational")
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Sort findings from highest to lowest risk score
    findings = sorted(
        findings,
        key=lambda finding: float(finding.get("risk_score", 0) or 0),
        reverse=True
    )
    # Generate remediation priority summary

    priority_order = {
        "Critical": 1,
        "High": 1,
        "Medium": 1,
        "Low": 2,
        "Informational": 3
    }

    remediation_priorities = []

    for finding in findings:
        severity = finding.get("severity", "Informational")
        remediation_priorities.append({
            "title": finding.get("title", "Untitled finding"),
            "severity": severity,
            "priority": priority_order.get(severity, 5),
            "recommendation": finding.get(
                "recommendation",
                "Review manually."
            )
        })

    remediation_priorities.sort(key=lambda item: item["priority"])

    findings = sorted(
        findings,
        key=lambda finding: float(finding.get("risk_score", 0) or 0),
        reverse=True
    )

    # Calculate overall risk rating
    highest_risk_score = max(
        (float(finding.get("risk_score", 0) or 0) for finding in findings),
        default=0.0
    )

    if highest_risk_score >= 8:
        overall_risk = "Critical"
    elif highest_risk_score >= 6:
        overall_risk = "High"
    elif highest_risk_score >= 3:
        overall_risk = "Medium"
    elif highest_risk_score > 0:
        overall_risk = "Low"
    else:
        overall_risk = "Informational" if findings else "No findings"
    # Build port table
    port_rows = []

    for host in hosts:
        address = ", ".join(host.get("addresses", [])) or "Unknown"

        for port in host.get("ports", []):
            port_rows.append(
                "<tr>"
                f"<td>{escape(str(address))}</td>"
                f"<td>{escape(str(port.get('port', '')))}</td>"
                f"<td>{escape(str(port.get('protocol', '')))}</td>"
                f"<td>{escape(str(port.get('state', '')))}</td>"
                f"<td>{escape(str(port.get('service', '')))}</td>"
                f"<td>{escape(str(port.get('product', '')))}</td>"
                "</tr>"
            )

    if not port_rows:
        port_rows.append(
            '<tr><td colspan="6">No port information available.</td></tr>'
        )    # Build security finding cards
    finding_cards = []

    for finding in findings:
        severity = finding.get("severity", "Informational")

        severity_class = (
            severity.lower()
            if severity in severity_counts
            else "informational"
        )

        finding_cards.append(f"""
        <div class="finding">
        <div class="finding-header">
        <strong>
            {escape(str(finding.get('id', 'N/A')))}
            - {escape(str(finding.get('title', 'Untitled finding')))}
         </strong>
         <span class="badge {severity_class}">
            {escape(str(severity))}
            </span>
            </div>
            <p><strong>Host:</strong>
                {escape(str(finding.get('host', 'Unknown')))}</p>

            <p><strong>Port:</strong>
                {escape(str(finding.get('port', 'Unknown')))}</p>

            <p><strong>Risk Score:</strong>
                {escape(str(finding.get('risk_score', 'Not assessed')))} / 10</p>

            <p><strong>Confidence:</strong>
                {escape(str(finding.get('confidence', 'Not assessed')))}</p>

            <p><strong>Impact:</strong>
                {escape(str(finding.get('impact', 'Not assessed')))}</p>

            <p><strong>Evidence:</strong></p>
            <pre>{escape(str(finding.get('evidence', 'No evidence provided')))}</pre>

            <p><strong>Recommendation:</strong>
                {escape(str(finding.get('recommendation', 'Review manually.')))}</p>
        </div>
        """)

    if not finding_cards:
        finding_cards.append("<p>No security findings were recorded.</p>")

    target = escape(str(report_data.get("target", "Unknown")))
    scan_date = escape(str(report_data.get("scan_date", "Unknown")))
    project = escape(str(report_data.get("project", "Automated Nmap Scanner")))
    scan_type = escape(str(report_data.get("scan_type", "Unknown")))

    html_document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment Report</title>

<style>
body {{
    font-family: Arial, sans-serif;
    background: #f3f4f6;
    color: #1f2937;
    margin: 0;
    padding: 30px;
}}

.container {{
    max-width: 1100px;
    margin: auto;
}}

header {{
    background: #172554;
    color: white;
    padding: 25px;
    border-radius: 10px;
}}

section {{
    background: white;
    padding: 22px;
    margin-top: 22px;
    border-radius: 10px;
}}

.summary {{
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
}}

.stat {{
    background: #e5e7eb;
    padding: 18px;
    border-radius: 8px;
    flex: 1;
    min-width: 120px;
}}

.stat strong {{
    display: block;
    font-size: 25px;
    margin-top: 8px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th, td {{
    padding: 12px;
    border-bottom: 1px solid #ddd;
    text-align: left;
}}

th {{
    background: #e5e7eb;
}}

.finding {{
    border: 1px solid #ddd;
    padding: 18px;
    margin: 15px 0;
    border-radius: 8px;
}}
.finding-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 12px;
}}

.finding-header strong {{
    flex: 1;
    min-width: 200px;
}}
}}

.badge {{
    padding: 5px 12px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: bold;
    white-space: nowrap;
}}

.high {{ background: #fecaca; color: #991b1b; }}
.medium {{ background: #fed7aa; color: #9a3412; }}
.low {{ background: #fef3c7; color: #92400e; }}
.informational {{ background: #dbeafe; color: #1e40af; }}

pre {{
    background: #f3f4f6;
    padding: 12px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
}}

footer {{
    text-align: center;
    margin-top: 25px;
    color: #6b7280;
    font-size: 13px;
}}
</style>
</head>

<body>
<div class="container">

<header>
    <h1>Security Assessment Report</h1>
    <p>{project}</p>
    <p><strong>Target:</strong> {target}</p>
    <p><strong>Scan date:</strong> {scan_date}</p>
    <p><strong>Scan type:</strong> {scan_type}</p>
</header>
<section>

<section>
    <h2>Executive Summary</h2>
    <div class="summary">
        <div class="stat">Overall Risk<strong>{overall_risk}</strong></div>
        <div class="stat">Hosts Scanned<strong>{total_hosts}</strong></div>
        <div class="stat">Ports Detected<strong>{total_ports}</strong></div>
        <div class="stat">Total Findings<strong>{len(findings)}</strong></div>
        <div class="stat">Critical<strong>{severity_counts["Critical"]}</strong></div>
        <div class="stat">High<strong>{severity_counts["High"]}</strong></div>
        <div class="stat">Medium<strong>{severity_counts["Medium"]}</strong></div>
        <div class="stat">Low<strong>{severity_counts["Low"]}</strong></div>
        <div class="stat">Informational<strong>{severity_counts["Informational"]}</strong></div>
    </div>
</section>

<section>
    <table>
        <thead>
        <tr>
            <th>Host</th>
            <th>Port</th>
            <th>Protocol</th>
            <th>State</th>
            <th>Service</th>
            <th>Product</th>
        </tr>
        </thead>
        <tbody>
            {''.join(port_rows)}
        </tbody>
    </table>
</section>

<section>
    <h2>Security Findings</h2>
    {''.join(finding_cards)}
</section>
<section>
    <h2>Remediation Priorities</h2>
    {''.join(
        f"""
        <div class="finding">
            <h3>Priority {item['priority']}: {escape(str(item['title']))}</h3>
            <p><strong>Severity:</strong> {escape(str(item['severity']))}</p>
            <p><strong>Recommended Action:</strong>
                {escape(str(item['recommendation']))}
            </p>
        </div>
        """
        for item in remediation_priorities
    ) if remediation_priorities else "<p>No remediation actions required.</p>"}
</section>
<section>
    <h2>Security Assessment Conclusion</h2>
    <p>
        The assessment identified {len(findings)} security findings
        across {total_hosts} scanned host(s).
        The overall risk rating is <strong>{overall_risk}</strong>.
    </p>
    <p>
        The identified issues should be reviewed and remediated
        according to their severity and potential business impact.
    </p>
    <p>
        All findings should be manually validated before being
        treated as confirmed vulnerabilities.
    </p>
</section>
<footer>
    Generated by Automated Nmap Scanner.
    Authorized security testing only.
    Findings require manual validation.
</footer>

</div>
</body>
</html>
"""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_document, encoding="utf-8")

    return output_path


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python3 html_report.py <scan.json>")
        sys.exit(1)

    json_file = Path(sys.argv[1])

    if not json_file.is_file():
        print("Error: JSON report file not found.")
        sys.exit(1)

    with json_file.open(encoding="utf-8") as file:
        report_data = json.load(file)

    html_file = json_file.with_suffix(".html")

    generate_html_report(report_data, html_file)

    print("\nHTML report generated successfully:")
    print(html_file.resolve())
