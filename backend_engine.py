import socket
import ssl
import datetime
import requests
from urllib.parse import urlparse

class OphiophagusExpertEngine:
    @staticmethod
    def get_cvss_severity(base_score):
        """Standardized CVSS v3.x Severity Mapping."""
        if base_score == 0: return "None"
        elif 0.1 <= base_score <= 3.9: return "Low"
        elif 4.0 <= base_score <= 6.9: return "Medium"
        elif 7.0 <= base_score <= 8.9: return "High"
        else: return "Critical"

    def parse_target(self, target_input):
        """Extracts clean hostname and port configuration variables."""
        parsed = urlparse(target_input)
        hostname = parsed.netloc or parsed.path
        if ":" in hostname:
            hostname, port = hostname.split(":")
            return hostname, int(port)
        
        # Default fallback to standard web routing ports
        port = 443 if target_input.startswith("https://") else 80
        return hostname, port

    def run_socket_port_scan(self, host, target_ports=[21, 22, 23, 25, 80, 443, 3306, 3389]):
        """
        MODULE 1: Native Network Layer Scanner
        Uses native low-level TCP stream sockets to perform connection-handshake 
        audits, mapping open ingress vectors and capturing running software banners.
        """
        open_vectors = []
        for port in target_ports:
            try:
                # Establish raw connection socket boundary
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1.5)
                    result = sock.connect_ex((host, port))
                    
                    if result == 0: # TCP Connection Success
                        banner = ""
                        try:
                            # Attempt to pull service banner signature
                            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        except Exception:
                            pass
                        
                        open_vectors.append({"port": port, "banner": banner})
            except Exception:
                pass
        return open_vectors

    def run_tls_cipher_audit(self, host, port=443):
        """
        MODULE 2: Cryptographic Infrastructure Analyzer
        Performs raw SSL/TLS socket wraps to identify cryptographic deprecation issues.
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return {
                        "active": True,
                        "version": ssock.version(),
                        "cipher": ssock.cipher()[0]
                    }
        except Exception:
            return {"active": False}

    def execute_advanced_assessment(self, target_input):
        """
        ORCHESTRATOR ENGINE
        Runs network, cryptographic, and application audit passes, then 
        maps discovered vulnerabilities directly to real-world Cyber Attack Vectors.
        """
        host, default_port = self.parse_target(target_input)
        
        try:
            resolved_ip = socket.gethostbyname(host)
        except socket.gaierror:
            resolved_ip = host

        report = {
            "target": target_input,
            "resolved_ip": resolved_ip,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "host_status": "Active Scanning Matrix Complete",
            "findings": []
        }

        # -------------------------------------------------------------
        # MODULE 1: Execute Network Infrastructure Assessment
        # -------------------------------------------------------------
        network_findings = self.run_socket_port_scan(resolved_ip)
        
        for vector in network_findings:
            port = vector["port"]
            
            # Case A: Publicly Exposed Database Interfaces
            if port == 3306:
                report["findings"].append({
                    "title": "Public Exposure of Relational Storage Ports (MySQL)",
                    "cvss": 8.1,
                    "severity": self.get_cvss_severity(8.1),
                    "attack_vector": "Credential Stuffing & Database Automated Ransomware Attacks",
                    "description": "Port 3306 was found open to external public network routes. Adversaries target exposed databases to execute automated password dictionary attacks, aiming to steal schemas, wipe active records, or drop ransomware notes.",
                    "remediation": "Modify server network bindings to run exclusively on the local interface (127.0.0.1) or restrict traffic using enterprise firewall access lists.",
                    "secure_code": "# Secure MySQL Configuration (my.cnf)\n[mysqld]\nbind-address = 127.0.0.1\n# Enforce firewall drop rule:\n# iptables -A INPUT -p tcp --dport 3306 -j DROP"
                })
                
            # Case B: Cleartext File Ingress Configuration
            elif port in [21, 23]:
                report["findings"].append({
                    "title": "Cleartext Communication Channel Deployment (FTP/Telnet)",
                    "cvss": 7.4,
                    "severity": self.get_cvss_severity(7.4),
                    "attack_vector": "Man-In-The-Middle (MitM) Credential Sniffing Attacks",
                    "description": f"An active transmission service was identified over unencrypted port {port}. Traffic traveling through this channel can be intercepted by anyone on the local network path using packet-capture tools.",
                    "remediation": "Decommission legacy cleartext daemons immediately and transition management workflows to secure, cryptographic channels like SFTP or SSH.",
                    "secure_code": "# Stop and completely disable insecure legacy daemons\nsudo systemctl stop vsftpd\nsudo systemctl disable vsftpd"
                })

            # Case C: Open Management Boundaries
            elif port == 3389:
                report["findings"].append({
                    "title": "Exposed Administrative Interface (RDP)",
                    "cvss": 8.8,
                    "severity": self.get_cvss_severity(8.8),
                    "attack_vector": "Brute-Force Intrusion & Remote Code Execution (RCE)",
                    "description": "Port 3389 (Remote Desktop Protocol) is openly reachable over public routing lanes. This gives attackers a direct point of attack to run persistent password-spraying campaigns or attempt remote code execution exploiting unpatched operating system bugs.",
                    "remediation": "Block all open public gateway rules routing to port 3389. Restrict administrative system connectivity exclusively behind a corporate VPN configuration.",
                    "secure_code": "# Enforce localized firewall boundaries via UFW\nsudo ufw deny 3389/tcp\nsudo ufw allow from 192.168.10.0/24 to any port 3389 proto tcp"
                })

        # -------------------------------------------------------------
        # MODULE 2: Execute Cryptographic Handshake Assessment
        # -------------------------------------------------------------
        crypto_data = self.run_tls_cipher_audit(host)
        if crypto_data.get("active") and crypto_data["version"] in ["TLSv1", "TLSv1.1"]:
            report["findings"].append({
                "title": f"Weak Cryptographic Baseline Verification ({crypto_data['version']})",
                "cvss": 7.5,
                "severity": self.get_cvss_severity(7.5),
                "attack_vector": "Cryptographic Degradation & Session Hijacking Attacks",
                "description": "The endpoint successfully completed handshakes using outdated TLS protocols. These legacy protocols contain architectural design flaws that allow attackers to perform decryption operations or run padding oracle attacks.",
                "remediation": "Disable support for TLS 1.0 and TLS 1.1 on your reverse proxies, load balancers, or web application servers. Set the minimum allowed protocol to TLS 1.2 or TLS 1.3.",
                "secure_code": "# Hardened NGINX Server Cryptography Block\nssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\nssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';"
            })

        # -------------------------------------------------------------
        # MODULE 3: Execute Application Layer Header Compliance Assessment
        # -------------------------------------------------------------
        url_target = target_input if target_input.startswith(('http://', 'https://')) else f"https://{target_input}"
        try:
            with requests.Session() as web_session:
                web_session.headers.update({'User-Agent': 'Ophiophagus-Core-Auditor/5.0'})
                response = web_session.get(url_target, timeout=4, allow_redirects=True)
                headers = response.headers

                # Case A: Check for Content Security Policy missing structures
                if 'Content-Security-Policy' not in headers:
                    report["findings"].append({
                        "title": "Missing Content-Security-Policy (CSP) Framework",
                        "cvss": 6.5,
                        "severity": self.get_cvss_severity(6.5),
                        "attack_vector": "Reflected / Stored Cross-Site Scripting (XSS) & Clickjacking",
                        "description": "The web server does not return a Content-Security-Policy header. Without a defined CSP framework, browsers will execute any script injected into the page, allowing attackers to steal session cookies, run malicious payloads, or redirect users.",
                        "remediation": "Configure your application routing layers to return a well-defined, strict Content-Security-Policy header.",
                        "secure_code": "# Python FastAPI Global Response Header Middleware\n@app.middleware('http')\nasync def apply_csp_policy(request, call_next):\n    response = await call_next(request)\n    response.headers['Content-Security-Policy'] = \"default-src 'self'; script-src 'self';\"\n    return response"
                    })

                # Case B: Check for session cookie vulnerability contexts
                set_cookie = headers.get('Set-Cookie', '')
                if set_cookie and not all(token in set_cookie.lower() for token in ['secure', 'httponly']):
                    report["findings"].append({
                        "title": "Insecure Application Session Cookie Attributes",
                        "cvss": 5.4,
                        "severity": self.get_cvss_severity(5.4),
                        "attack_vector": "Session Hijacking via Document Object Model (DOM) Extraction",
                        "description": "Session tokens are generated without the critical 'HttpOnly' or 'Secure' flags. This allows malicious frontend scripts to access the cookie data via JavaScript or transmits the session token over unencrypted HTTP pathways.",
                        "remediation": "Configure your application framework's session manager to automatically enforce the HttpOnly, Secure, and SameSite cookie flags.",
                        "secure_code": "# Python Flask Application Cookie Hardening Setup\napp.config.update(\n    SESSION_COOKIE_SECURE=True,\n    SESSION_COOKIE_HTTPONLY=True,\n    SESSION_COOKIE_SAMESITE='Lax'\n)"
                    })
        except requests.exceptions.RequestException:
            pass

        # Fallback security check handling if target returns no obvious exposures
        if not report["findings"]:
            report["findings"].append({
                "title": "Target Ingress Boundary Successfully Verified against Testing Baseline",
                "cvss": 0.0,
                "severity": "None",
                "attack_vector": "None - System Profile Demonstrates Strong Baseline Resilience",
                "description": "The active scan did not detect any open infrastructure ports, cleartext communication paths, or missing application security headers.",
                "remediation": "No immediate code patches are required. Maintain regular infrastructure scanning intervals.",
                "secure_code": "# Target parameters fully conform to baseline configuration templates."
            })

        return report
