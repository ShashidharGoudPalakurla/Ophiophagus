🐍 Ophiophagus AI Pentester
An enterprise-grade, autonomous network and web application penetration testing suite. Developed with a high-performance Python core and a secure Streamlit frontend interface, Ophiophagus executes live socket handshakes, raw transport-layer packet inspection, and real-time application banner fuzzing to isolate hidden security vulnerabilities, compute accurate CVSS v3.x metrics, map flaws to direct Cyber Attack Vectors, and deliver drop-in secure source code remedies.

🎯 Core Features
Multi-Tier Dynamic Scanning: Implements independent, decoupled auditing threads for infrastructure ports, cryptographic configurations, and web application components.

Low-Level Protocol Auditing: Bypasses conventional browser abstraction constraints using raw Python sockets and custom network handshake evaluations.

Cryptographic Compliance Verification: Probes active remote cryptographic endpoints to detect and flag insecure TLS protocols (TLS 1.0/1.1) and weak ciphers.

Threat Matrix Orchestration: Translates ambiguous technical indicators instantly into quantified industry-standard CVSS v3.x impact metrics.

Cyber Attack Vector Mapping: Explicitly exposes the underlying security risks associated with findings, clarifying exactly how an adversary targets the vulnerability (e.g., Remote Code Execution, Ransomware, Session Hijacking).

Dynamic Source Code Remediation: Automatically outputs secure, production-ready code patches tailored directly for frameworks like FastAPI, Flask, and Nginx configurations to close the feedback loop for developers.

Secure Session Router Management: Features a built-in user gateway backed by encrypted cookie tracking parameters and persistent session audit history tables.

🏗️ System Architecture
The tool is split into independent presentation, orchestration, and technical auditing layers to guarantee maximum execution stability:

Plaintext
         ┌───────────────────────────────────────────┐
         │             Operator Browser              │
         │          (Streamlit Frontend UI)          │
         └─────────────────────┬─────────────────────┘
                               │ HTTPS / WebSockets
                               ▼
         ┌───────────────────────────────────────────┐
         │     Streamlit Web Server & Authenticator  │
         │         Python Backend Orchestrator       │
         └─────────────────────┬─────────────────────┘
                               │ Authorized Requests
                               ▼
         ┌───────────────────────────────────────────┐
         │       Ophiophagus Core Expert Engine      │
         │           (backend_engine.py)             │
         └─────────────┬───────────────┬─────────────┘
                       │               │
         ┌─────────────┴┐              ┴─────────────┐
         ▼                             ▼             ▼
┌──────────────────────────────┐ ┌──────────────────────────────┐
│  Network Layer Modules       │ │ Web App Layer Modules        │
├──────────────────────────────┤ ├──────────────────────────────┤
│ - Native Socket Scanner      │ │ - HTTP Response Auditor      │
│ - Banner Fingerprinting      │ │ - Header & Cookie Analyzer   │
│ - TLS & Crypto Handshake     │ │ - HTML BeautifulSoup Parser  │
└──────────────────────────────┘ └──────────────────────────────┘
📦 Project Directory Structure
Plaintext
ophiophagus_project/
│
├── app.py                 # Primary Application Gateway (Authentication, Routing, Layout)
├── backend_engine.py      # Core Expert Engine (Socket Probes, TLS Wrap, App Auditor)
├── config.yaml            # Environment Access Credentials & Security Parameters
└── requirements.txt       # Unified System Dependencies
🛠️ Installation & Setup
📋 Prerequisites
The lower-level network mapping tools require native cryptographic components and development headers on the host machine.

For Debian/Ubuntu-Based Systems (Kali Linux, Parrot OS, Ubuntu):
Bash
sudo apt-get update && sudo apt-get install -y nmap libpcap-dev python3-dev
For macOS:
Bash
brew install nmap
🗂️ Environment Setup
Clone or copy the project files into a dedicated repository folder.

Initialize and activate a safe Python virtual environment:

Bash
python3 -m venv venv
source venv/bin/activate
Install the required dependency matrix using your environment package manager:

Bash
pip install --upgrade pip
pip install -r requirements.txt
⚙️ Configuration (config.yaml)
Configure your system operator user authentication matrix within the config.yaml boundary.

YAML
credentials:
  usernames:
    admin:
      email: "admin@ophiophagus.local"
      name: "Security Lead"
      password: "admin123" # Input strings are evaluated securely against structural verification keys
cookie:
  expiry_days: 30
  key: "ophiophagus_secure_signature_key"
  name: "ophiophagus_auth_cookie"
🏁 Execution Parameters
Because the backend engine interfaces with native kernel structures to perform low-level TCP connection evaluations and handle packet operations, launch the application shell with elevated administrative system privileges:

Bash
sudo python3 -m streamlit run app.py
🔑 Default Workspace Credentials:
Username: admin

Password: admin123

🛡️ Operational Testing Workflow
Authentication Portal: Enter the operator credentials at the central security lock window.

Dashboard Operation: Input your target parameters (e.g., 192.168.1.1 or example.com) into the centralized testing console.

Active Interrogation: The framework fires parallel low-level network checks, tests cryptographic capabilities, and processes app headers.

Threat Modeling Panel: Evaluate your target's risk profile instantly via real-time Plotly density charts and vulnerability breakdowns.

Remediation Implementation: Expand any identified threat report to copy the corresponding Cyber Attack Vector description and drop-in security source code patch to harden your system code.

Session Logging: Navigate to the Session Audit Logs repository view to review the aggregated results compiled during the runtime lifecycle.

🛑 Legal Disclaimer
WARNING: The Ophiophagus AI Pentester framework is designed strictly for authorized security research, corporate compliance validation, and authorized ethical penetration testing scenarios. Executing active network fuzzer sweeps or low-level port socket connection handshakes against infrastructure assets without explicit, written cryptographic authorization from the system owners is illegal and constitutes a violation of computer fraud laws. Users assume full liability for compliance with local regulations.
