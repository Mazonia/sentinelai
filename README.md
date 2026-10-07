# 🛡️ SentinelAI — AI Offensive Security & Vulnerability Arsenal

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Security-AppSec%20%7C%20DAST%20%7C%20Recon-red?style=for-the-badge&logo=shield" alt="AppSec">
  <img src="https://img.shields.io/badge/AI_Engine-Llama--3.3%20%7C%20OpenAI-purple?style=for-the-badge&logo=openai" alt="AI Engine">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen?style=for-the-badge" alt="PRs Welcome">
</p>

> **SentinelAI** is an advanced, all-in-one AI-powered offensive security framework, automated vulnerability scanner, and penetration testing arsenal. Combining instant reconnaissance, deep web vulnerability audits, automated false-positive reduction, and a curated multi-tool launchpad into a seamless terminal and web experience.

---

```
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗ ██╗
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗██║
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║██║
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║██║
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║██║
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝
      ⚡ AI-POWERED OFFENSIVE SECURITY & PENETRATION TESTING ARSENAL ⚡
```

---

## 🚀 Key Highlights & Capabilities

### 1. 🧰 Curated Security Tools Arsenal *(Inspired by hackingtool)*
Instant host environment detection and one-click launchpad for 15+ industry-standard security tools:
- **Port & Network Scanning**: Nmap, RustScan, Masscan
- **Web Vulnerability Scanning**: Nikto, Nuclei, Wapiti, WPScan
- **Content & Directory Fuzzing**: Gobuster, FFuF, Dirsearch
- **Database & Injection**: SQLmap, Ghauri
- **OSINT & Recon**: Sublist3r, WhatWeb, Whois
- **SSL / TLS Auditing**: testssl.sh, SSLyze

### 2. 🔍 Standalone Reconnaissance & OSINT Engine
- **Subdomain Discovery**: High-speed discovery via Certificate Transparency (crt.sh) & asynchronous DNS resolution.
- **Port Scanner**: Multi-threaded TCP connect scanner targeting top operational service ports.
- **WAF & Firewall Fingerprinting**: Automatic detection for Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, and ModSecurity.
- **Tech Stack Identification**: Identifies Nginx, Apache, WordPress, React, Next.js, Django, Laravel, and exposed server versions.

### 3. 🎯 Deep Web Application Vulnerability Scanner
- **SQL Injection (SQLi)**: Error-based, boolean-based, and union-based injection audit.
- **Cross-Site Scripting (XSS)**: Reflected, DOM-based, and attribute-context script injection checks.
- **Security Misconfigurations**: Missing HSTS, CSP, X-Frame-Options clickjacking protection, and CORS reflection.
- **Sensitive File & Information Disclosure**: Audits `/.env`, `/.git`, backup dumps, Swagger docs, and configuration files.
- **API & Authentication Auditing**: Discovers REST/GraphQL endpoints, JWT signing flaws, and IDOR patterns.

### 4. 🤖 AI Vulnerability Analysis & Remediation
- Uses LLM engines (**Llama-3.3-70b via Groq**, **OpenAI GPT-4o-mini**, or **Local Heuristic Engine**) to analyze findings.
- **False-Positive Elimination**: Eliminates harmless scanner noise.
- **CVSS 3.1 Scoring**: Calculates realistic risk scores and business impact.
- **Copy-Paste Code Patches**: Generates precise remediation code for developers in Python, PHP, JavaScript, and server configs.

### 5. 📄 Executive & Technical Security Reports
- **Cyberpunk Dark HTML Reports**: Executive summary, severity distributions, and technical evidence cards.
- **Markdown Reports**: Perfect for bug bounty platform writeups (HackerOne, Bugcrowd).
- **JSON Reports**: Machine-readable data for automated DevSecOps pipelines.

---

## ⚡ Quick Start

### 1. Clone & Setup
```bash
git clone https://github.com/Mazonia/sentinelai.git
cd sentinelai
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Interactive Terminal Dashboard (Zero Setup)
```bash
python -m sentinelai.cli.main
# Or on Windows double-click: run_cli.bat
```

### 3. CLI Direct Subcommands
```bash
# Full Automated Scan with AI Remediation:
python -m sentinelai.cli.main scan https://example.com

# Domain Reconnaissance & OSINT:
python -m sentinelai.cli.main recon example.com

# Launch Security Tool Arsenal:
python -m sentinelai.cli.main tools
```

---

## 🐳 Optional: Distributed Docker & Web UI Mode

If you wish to run the full distributed cluster with PostgreSQL, Redis, Celery, and the React Web Dashboard:

```bash
cp .env.example .env
docker compose up -d
```
Access the web dashboard at: `http://localhost:3000`  
FastAPI Backend documentation: `http://localhost:8000/docs`

---

## ⚖️ Legal & Ethical Disclaimer
SentinelAI is developed for authorized penetration testing, security auditing, vulnerability assessment, and educational research purposes only. Do not scan targets without prior written authorization from the system owners.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
