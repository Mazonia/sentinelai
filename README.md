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
Instant host environment detection, 1-click auto-installation, live execution streaming, and evidence logging for 26+ industry-standard security tools across 10 categories:
- **Network Discovery & Port Auditing**: Nmap, RustScan, Masscan, Netcat (nc)
- **Web Vulnerability & DAST Scanners**: Nikto, Nuclei, Wapiti
- **CMS & Framework Auditing**: WPScan, CMSmap, Droopescan
- **Directory, File & Parameter Fuzzing**: Gobuster, FFuF, Dirsearch, Feroxbuster
- **Database & SQL Injection Auditing**: SQLmap, Ghauri
- **OSINT & Subdomain Intelligence**: Sublist3r, WhatWeb, Whois, theHarvester
- **DNS & Infrastructure Enumeration**: Dnsrecon, Dnsenum
- **SSL / TLS & Cipher Auditing**: testssl.sh, SSLyze
- **Secrets & Repository Intelligence**: TruffleHog
- **Web Parameter & Route Spidering**: ParamSpider

### 2. ⚡ Multi-Task Automated Workflows (Chained 1-Click Tasks)
- **Perimeter & Infrastructure Recon**: DNS + crt.sh Subdomains + 22 Ports + WAF + Security Headers (~10s).
- **Content & Sensitive File Discovery**: Web Crawl + 50 Paths + Configs + Backups + LFI (~25s).
- **API & Endpoint Attack Surface**: Swagger/OpenAPI + GraphQL + CORS + SSRF Vectors (~20s).
- **Complete Full-Scope Assessment**: End-to-end full audit suite with AI correlation and false-positive elimination.

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

### 2. Interactive Numbered Console (Zero Typing Required)
Simply type `sentinelai` (or `sentinel`) — no python prefixes or complex syntax needed:
```bash
sentinelai
```
This launches the guided numbered console:
```text
[1] ⚡ Multi-Task Assessment Workflows (1-Click Chained Presets: Perimeter, Content, API, Full)
[2] 🎯 Full Deep Vulnerability Scan (Crawl, OWASP Audit Suite, AI Analysis & Report)
[3] 🔍 Reconnaissance & OSINT Engine (DNS, Subdomains, 22-Port Scanner, WAF Identification)
[4] 📂 Fast Sensitive File Fuzzer (Probes .env, .git, backups, SQL dumps, APIs)
[5] 🧪 Targeted Vulnerability Tester (Directly audit SQLi, XSS, CORS, SSRF, LFI, Headers)
[6] 🧰 Security Tools Arsenal (26+ Tools across 10 Categories with 1-Click Auto-Install & Logs)
[7] 📄 View & Open Audit Reports (Browse, read, and 1-click open Cyberpunk HTML reports)
[8] 🌐 Start SentinelAI REST API Server (Launch FastAPI backend on localhost:8000)
[9] 🎯 Set / Change Active Target (Configure session memory target)
[0] 🚪 Exit
```
Just enter a number (`1`, `2`, `3`...). SentinelAI guides you through each step and remembers your active target so you rarely have to re-type anything!

### 3. Optional Direct Shorthand Commands
You can also run direct actions by passing arguments to `sentinelai`:
```bash
# Full Automated Scan with AI Remediation & Report Generation:
sentinelai scan https://example.com

# Domain Reconnaissance & OSINT:
sentinelai recon example.com

# Sensitive File & Hidden Path Fuzzing:
sentinelai fuzz https://example.com

# Launch Security Tool Arsenal:
sentinelai tools

# Browse & open generated reports:
sentinelai reports

# Start REST API backend:
sentinelai api
```

### 4. Running Tests
```bash
pytest -v
```

---

## 🌐 FastAPI REST API Endpoints

SentinelAI provides a REST API that powers the web dashboard and integrates into automated DevSecOps pipelines:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/recon/{domain}` | Instant OSINT, DNS resolution, open port scanning, and WAF identification |
| `GET` | `/api/v1/tools` | Curated security tools inventory with local host installation detection |
| `POST` | `/api/v1/fuzz` | Fast sensitive path & file fuzzer with soft-404 wildcard filtering |
| `POST` | `/api/v1/quick-scan` | Asynchronous standalone scan with zero database dependencies |
| `GET` | `/api/v1/reports` | Index of all generated HTML, Markdown, and JSON audit reports |
| `GET` | `/api/v1/reports/{filename}` | Interactive view or download of generated security reports |
| `POST` | `/api/v1/scan` | Distributed cluster scan (uses PostgreSQL + Celery workers) |
| `GET` | `/api/v1/scan/{id}/status` | Real-time status polling for distributed scans |

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
