# 🛡️ SentinelAI — AI Offensive Security & Vulnerability Arsenal

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-0078D6?style=for-the-badge&logo=windows" alt="Cross-Platform">
  <img src="https://img.shields.io/badge/Security-AppSec%20%7C%20DAST%20%7C%20Threat%20Modeling-red?style=for-the-badge&logo=shield" alt="AppSec">
  <img src="https://img.shields.io/badge/AI_Engine-Groq%20%7C%20OpenAI%20%7C%20Venice%20%7C%20DeepSeek-purple?style=for-the-badge&logo=openai" alt="AI Engine">
  <img src="https://img.shields.io/badge/Copilot-Interactive%20Terminal%20Advisor-cyan?style=for-the-badge&logo=terminal" alt="Copilot">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License">
</p>

> **SentinelAI** is an advanced, all-in-one AI-powered offensive security framework, automated vulnerability scanner, and penetration testing arsenal. Combining instant reconnaissance, deep web vulnerability audits, automated threat modeling, CVSS 3.1 calculations, copy-paste developer remediation patches, an interactive AI Security Copilot, and a curated multi-tool launchpad into a seamless terminal and web experience.

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

### 🪟 100% Native Windows & Linux Cross-Platform Architecture
SentinelAI is fully engineered to run seamlessly across **Windows 10/11**, **Linux**, and **macOS**:
- **Windows Package Manager (`winget`) & Chocolatey (`choco`)**: 1-click install industry-standard external tools directly from the terminal console.
- **Smart Path Resolver**: Automatically locates tools in `C:\Program Files`, `C:\Program Files (x86)`, WinGet Links, Chocolatey bin, Scoop shims, and virtual environment `Scripts/`.
- **Zero-Setup SQLite Mode**: Embedded database fallback ensures scans and API servers run natively on Windows without requiring Docker, PostgreSQL, or WSL.
- **Windows Console ANSI & UTF-8**: Automatic Virtual Terminal Processing (VT100) initialization guarantees crystal-clear cyberpunk colors, bold borders, and emoji icons in Windows Command Prompt (CMD), PowerShell, and Windows Terminal.
- **Windows Celery Compatibility**: Automatically activates the `solo` pool on Windows to eliminate Linux `fork()` compatibility errors.

### 1. 🤖 Next-Gen AI Security Engine & Threat Modeling
- **Multi-Provider LLM Integration**: Connects to **Groq (`llama-3.3-70b-versatile`)**, **OpenAI (`gpt-4o-mini`)**, **Venice AI (`llama-3.3-70b`)**, and **DeepSeek (`deepseek-chat`)** with automatic multi-provider failover.
- **Offline Heuristic Engine**: Built-in comprehensive rule and pattern database guarantees full scoring and remediation capabilities with **zero API keys required**.
- **Automated Holistic Threat Modeling**: Correlates perimeter reconnaissance, open ports, technologies, and vulnerabilities into an executive posture rating (`CRITICAL`, `HIGH`, `MEDIUM`), primary threat vectors, immediate 24-hour actions, and strategic roadmaps.
- **CVSS 3.1 Scoring & Vectors**: Calculates standardized CVSS 3.1 vector strings (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) and exploit complexity metrics.
- **Developer Remediation Code Patches**: Generates precise, copy-paste defensive patches for Python, PHP, JavaScript, SQL, and Nginx/Apache web server configurations.

### 2. 💬 Interactive AI Security Copilot (Terminal Chat Mode)
- **Context-Aware Technical Advisory**: The Copilot automatically ingests the active target, detected WAF, open ports, and discovered vulnerabilities.
- **On-Demand Penetration Testing Guidance**: Ask the Copilot technical questions right inside the terminal:
  - *"How do I verify if this SQL injection is vulnerable to time-based exfiltration?"*
  - *"Generate the secure Nginx configuration to enforce HSTS and CSP."*
  - *"Explain the business impact of this CORS misconfiguration to an executive."*
- **Post-Scan 1-Click Consultation**: Launch Copilot directly from the scan summary to immediately interrogate findings.

### 3. 🧰 Curated Security Tools Arsenal *(Inspired by hackingtool)*
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

### 4. ⚡ Multi-Task Automated Workflows (Chained 1-Click Tasks)
- **Perimeter & Infrastructure Recon**: DNS + crt.sh Subdomains + 22 Ports + WAF + Security Headers (~10s).
- **Content & Sensitive File Discovery**: Web Crawl + 50 Paths + Configs + Backups + LFI (~25s).
- **API & Endpoint Attack Surface**: Swagger/OpenAPI + GraphQL + CORS + SSRF Vectors (~20s).
- **Complete Full-Scope Assessment**: End-to-end full audit suite with AI correlation and false-positive elimination.

### 5. 🔍 Standalone Reconnaissance & OSINT Engine
- **Subdomain Discovery**: High-speed discovery via Certificate Transparency (crt.sh) & asynchronous DNS resolution.
- **Port Scanner**: Multi-threaded TCP connect scanner targeting top operational service ports.
- **WAF & Firewall Fingerprinting**: Automatic detection for Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, and ModSecurity.
- **Tech Stack Identification**: Identifies Nginx, Apache, WordPress, React, Next.js, Django, Laravel, and exposed server versions.

### 6. 🎯 Deep Web Application Vulnerability Scanner
- **SQL Injection (SQLi)**: Error-based, boolean-based, and union-based injection audit.
- **Cross-Site Scripting (XSS)**: Reflected, DOM-based, and attribute-context script injection checks.
- **Security Misconfigurations**: Missing HSTS, CSP, X-Frame-Options clickjacking protection, and CORS reflection.
- **Sensitive File & Information Disclosure**: Audits `/.env`, `/.git`, backup dumps, Swagger docs, and configuration files.
- **API & Authentication Auditing**: Discovers REST/GraphQL endpoints, JWT signing flaws, and IDOR patterns.

### 7. 📄 Executive & Technical Security Reports
- **Cyberpunk Dark HTML Reports**: Executive summary, AI threat model card, risk distributions, CVSS vector badges, and syntax-highlighted code patches.
- **Markdown Reports**: Formatted with executive summaries and developer patches, ready for HackerOne, Bugcrowd, or internal wikis.
- **JSON Reports**: Machine-readable data for automated DevSecOps pipelines.

---

## ⚡ Quick Start

### 🪟 Windows Quick Start (1-Click Automated Setup)

#### Option A: 1-Click Batch Installer
Simply double-click `install_windows.bat` (or run in Command Prompt):
```cmd
git clone https://github.com/Mazonia/sentinelai.git
cd sentinelai
install_windows.bat
```
This automatically sets up Python virtual environments, installs requirements, registers global `sentinelai` commands, and launches the console.

#### Option B: PowerShell Setup
```powershell
git clone https://github.com/Mazonia/sentinelai.git
cd sentinelai
.\install_windows.ps1
```

Once installed, simply type `sentinelai` or `.\sentinelai.ps1` in any terminal!

---

### 🐧 Linux & macOS Quick Start

#### Option A: 1-Click Automated Script
```bash
git clone https://github.com/Mazonia/sentinelai.git
cd sentinelai
chmod +x install_linux.sh sentinel.sh
./install_linux.sh
```
This automatically sets up the Python virtual environment, installs dependencies, registers global `sentinelai` commands in `~/.local/bin`, and launches the framework!

#### Option B: Manual Setup
```bash
git clone https://github.com/Mazonia/sentinelai.git
cd sentinelai
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
sentinelai
```

> **Headless Server Support**: On headless Linux VPS/cloud servers (without a desktop GUI/browser), SentinelAI automatically detects the environment and provides direct absolute file paths for HTML/Markdown reports without throwing `xdg-open` browser launch errors.

### 2. Interactive Numbered Console (Zero Typing Required)
Simply type `sentinelai` (or `sentinel`) — no python prefixes or complex syntax needed:
```bash
sentinelai
```
This launches the guided numbered console:
```text
[1] ⚡ Multi-Task Assessment Workflows (1-Click Chained Presets: Perimeter, Content, API, Full)
[2] 🎯 Full Deep Vulnerability Scan (Crawl, OWASP Audit Suite, AI Threat Model & Report)
[3] 🔍 Reconnaissance & OSINT Engine (DNS, Subdomains, 22-Port Scanner, WAF Identification)
[4] 📂 Fast Sensitive File Fuzzer (Probes .env, .git, backups, SQL dumps, APIs)
[5] 🧪 Targeted Vulnerability Tester (Directly audit SQLi, XSS, CORS, SSRF, LFI, Headers)
[6] 🧰 Security Tools Arsenal (26+ Tools across 10 Categories with 1-Click Auto-Install & Logs)
[7] 📄 View & Open Audit Reports (Browse, read, and 1-click open Cyberpunk HTML reports)
[8] 🤖 Interactive AI Security Copilot (Terminal chat, threat reasoning, and remediation code)
[9] 🌐 Start SentinelAI REST API Server (Launch FastAPI backend on localhost:8000)
[10] 🎯 Set / Change Active Target (Configure session memory target)
[0] 🚪 Exit
```
Just enter a number (`1`, `2`, `3`...). SentinelAI guides you through each step and remembers your active target so you rarely have to re-type anything!

### 3. Optional Direct Shorthand Commands
You can also run direct actions by passing arguments to `sentinelai`:
```bash
# Full Automated Scan with AI Remediation & Report Generation:
sentinelai scan https://example.com

# Launch Interactive AI Security Copilot:
sentinelai copilot

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

### 4. Configuring AI Providers (Optional)
To enable live LLM reasoning, export any of the supported API keys:
```bash
# Groq (Ultra-fast Llama-3.3-70b - Recommended)
export GROQ_API_KEY="gsk_..."

# OpenAI
export OPENAI_API_KEY="sk-..."

# DeepSeek
export DEEPSEEK_API_KEY="sk-..."

# Venice AI
export VENICE_API_KEY="..."
```
*Note: If no API keys are set, SentinelAI automatically uses its built-in offline Heuristic Rule Engine with zero configuration.*

### 5. Running Tests
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
