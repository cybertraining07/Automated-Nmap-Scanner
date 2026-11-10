def analyze_scan(scan_data):
    """Analyze Nmap results and return prioritized security findings."""

    findings = []

    for host in scan_data.get("hosts", []):
        addresses = host.get("addresses", [])
        host_ip = addresses[0] if addresses else "Unknown"

        for port in host.get("ports", []):
            port_number = port.get("port", "Unknown")

            for script in port.get("scripts", []):
                script_id = script.get("id", "")
                output = script.get("output", "")
                if script_id == "http-headers" and output.strip():

                    observed_headers = set()

                    for line in output.splitlines():
                        clean_line = line.strip().lstrip("|_ ").strip()

                        if ":" in clean_line:
                            header_name = clean_line.split(":", 1)[0].strip().lower()
                            observed_headers.add(header_name)

                    security_headers = [
                        "content-security-policy",
                        "strict-transport-security",
                        "x-frame-options",
                        "x-content-type-options",
                        "referrer-policy",
                        "permissions-policy"
                    ]

                    is_https = (
                        str(port_number) == "443"
                        or str(port.get("service", "")).lower() == "https"
                    )

                    missing_headers = [
                        header for header in security_headers
                        if header not in observed_headers
                        and (header != "strict-transport-security" or is_https)
                    ]

                    if missing_headers:
                        findings.append({
                            "id": "HTTP-004",
                            "title": "Missing HTTP Security Headers",
                            "severity": "Low",
                            "risk_score": 3.0,
                            "confidence": "Medium",
                            "host": host_ip,
                            "port": port_number,
                            "evidence": (
                                "Missing headers: "
                                + ", ".join(missing_headers)
                            ),
                            "impact": (
                                "Missing security headers may reduce "
                                "browser-side protections against attacks "
                                "such as clickjacking and cross-site scripting."
                            ),
                            "recommendation": (
                                "Review the web application's security "
                                "requirements and configure appropriate "
                                "HTTP security response headers."
                            )
                        })

                if (
                    script_id == "http-title"
                    and "directory listing for" in output.lower()
                ):
                    findings.append({
                        "id": "HTTP-001",
                        "title": "HTTP Directory Listing Enabled",
                        "severity": "Medium",
                        "risk_score": 5.0,
                        "confidence": "High",
                        "host": host_ip,
                        "port": port_number,
                        "evidence": output.strip(),
                        "impact": (
                            "Exposed directory contents may reveal files "
                            "or information that should not be public."
                        ),
                        "recommendation": (
                            "Disable directory listing unless required. "
                            "Review the web root for sensitive files."
                        )
                    })

                if (
                    script_id == "http-headers"
                    and "server:" in output.lower()
                ):
                    findings.append({
                        "id": "HTTP-002",
                        "title": "HTTP Server Information Disclosure",
                        "severity": "Informational",
                        "risk_score": 0.0,
                        "confidence": "High",
                        "host": host_ip,
                        "port": port_number,
                        "evidence": output.strip(),
                        "impact": (
                            "Server details may help identify the "
                            "software running on the web server."
                        ),
                        "recommendation": (
                            "Consider minimizing unnecessary server "
                            "version information in HTTP response headers."
                        )
                    })

                if script_id == "http-methods":
                    methods = output.upper()

                    risky_methods = [
                        method for method in ["PUT", "DELETE", "TRACE"]
                        if method in methods
                    ]

                    if risky_methods:
                        findings.append({
                            "id": "HTTP-003",
                            "title": "Potentially Risky HTTP Methods Enabled",
                            "severity": "Medium",
                            "risk_score": 5.0,
                            "confidence": "Medium",
                            "host": host_ip,
                            "port": port_number,
                            "evidence": ", ".join(risky_methods),
                            "impact": (
                                "Unnecessary HTTP methods may increase "
                                "the attack surface if access controls "
                                "are improperly configured."
                            ),
                            "recommendation": (
                                "Review whether these methods are required. "
                                "Restrict unnecessary methods and verify "
                                "authorization controls."
                            )
                        })

    return findings
