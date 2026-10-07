"""
Curated Security Tools Arsenal & High-Efficiency Launcher
Inspired by hackingtool, featuring automated environment detection,
1-click package auto-installation, live output logging, and report integration.
"""
import shutil
import subprocess
import sys
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

ARSENAL_CATEGORIES: Dict[str, List[Dict[str, Any]]] = {
    "1. Network Discovery & Port Auditing": [
        {
            "name": "Nmap",
            "cmd": "nmap",
            "desc": "Network exploration tool, service version detection & security scanner",
            "install": "winget install Insecure.Nmap (Windows) or sudo apt install nmap (Linux)",
            "pip_pkg": None,
            "preset_quick": "{cmd} -F -Pn {target}",
            "preset_deep": "{cmd} -sV -sC -Pn -T4 {target}",
            "preset": "{cmd} -sV -sC -Pn {target}"
        },
        {
            "name": "RustScan",
            "cmd": "rustscan",
            "desc": "Modern port scanner with ultra-fast asynchronous SYN scanning",
            "install": "cargo install rustscan or winget install rustscan",
            "pip_pkg": None,
            "preset_quick": "{cmd} -a {target} --range 1-1000",
            "preset_deep": "{cmd} -a {target} --ulimit 5000 -- -sV",
            "preset": "{cmd} -a {target} --ulimit 5000"
        },
        {
            "name": "Masscan",
            "cmd": "masscan",
            "desc": "High-volume TCP port scanner capable of scanning entire networks",
            "install": "sudo apt install masscan",
            "pip_pkg": None,
            "preset_quick": "{cmd} {target} -p80,443,8080,8443 --rate=1000",
            "preset_deep": "{cmd} {target} -p1-65535 --rate=2000",
            "preset": "{cmd} {target} -p1-65535 --rate=1000"
        },
        {
            "name": "Netcat (nc)",
            "cmd": "nc",
            "desc": "Arbitrary TCP and UDP port connections, banner grabbing, and port listening",
            "install": "ncat via nmap or sudo apt install netcat",
            "pip_pkg": None,
            "preset_quick": "{cmd} -zv {target} 80 443",
            "preset_deep": "{cmd} -v -w 3 {target} 21-443",
            "preset": "{cmd} -zv {target} 80 443"
        }
    ],
    "2. Web Vulnerability & DAST Scanners": [
        {
            "name": "Nikto",
            "cmd": "nikto",
            "desc": "Comprehensive web server scanner for dangerous files, outdated software & CGIs",
            "install": "sudo apt install nikto or git clone https://github.com/sullo/nikto",
            "pip_pkg": None,
            "preset_quick": "{cmd} -h {target} -Tuning 1,2",
            "preset_deep": "{cmd} -h {target} -C all",
            "preset": "{cmd} -h {target}"
        },
        {
            "name": "Nuclei",
            "cmd": "nuclei",
            "desc": "Fast and customizable vulnerability scanner based on community YAML templates",
            "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "pip_pkg": None,
            "preset_quick": "{cmd} -u {target} -t cves/ -severity critical,high",
            "preset_deep": "{cmd} -u {target} -severity critical,high,medium,low",
            "preset": "{cmd} -u {target} -severity critical,high,medium"
        },
        {
            "name": "Wapiti",
            "cmd": "wapiti",
            "desc": "Web application vulnerability scanner (audits XSS, SQLi, SSRF, XXE)",
            "install": "pip install wapiti3",
            "pip_pkg": "wapiti3",
            "preset_quick": "{cmd} -u {target} -m xss,sql --depth 1",
            "preset_deep": "{cmd} -u {target} --flush-session --all",
            "preset": "{cmd} -u {target} --flush-session"
        }
    ],
    "3. CMS & Framework Auditing": [
        {
            "name": "WPScan",
            "cmd": "wpscan",
            "desc": "WordPress security scanner auditing themes, plugins, and core vulnerabilities",
            "install": "gem install wpscan or docker run --rm wpscanteam/wpscan",
            "pip_pkg": None,
            "preset_quick": "{cmd} --url {target} --enumerate p",
            "preset_deep": "{cmd} --url {target} --enumerate vp,vt,tt,cb,dps,u",
            "preset": "{cmd} --url {target} --enumerate vp,vt,tt,cb,dps,u"
        },
        {
            "name": "CMSmap",
            "cmd": "cmsmap",
            "desc": "Python open-source CMS scanner for WordPress, Joomla, Drupal, and Moodle",
            "install": "pip install cmsmap or git clone https://github.com/Dionach/CMSmap.git",
            "pip_pkg": "cmsmap",
            "preset_quick": "{cmd} {target} -f W",
            "preset_deep": "{cmd} {target} -a",
            "preset": "{cmd} {target}"
        },
        {
            "name": "Droopescan",
            "cmd": "droopescan",
            "desc": "Plugin-based scanner for Drupal, Silverstripe, and WordPress",
            "install": "pip install droopescan",
            "pip_pkg": "droopescan",
            "preset_quick": "{cmd} scan drupal -u {target}",
            "preset_deep": "{cmd} scan drupal -u {target} --enumerate-all",
            "preset": "{cmd} scan drupal -u {target}"
        }
    ],
    "4. Directory, File & Parameter Fuzzing": [
        {
            "name": "Gobuster",
            "cmd": "gobuster",
            "desc": "High-performance directory/file, DNS, and VHost busting tool written in Go",
            "install": "go install github.com/OJ/gobuster/v3@latest",
            "pip_pkg": None,
            "preset_quick": "{cmd} dir -u {target} -t 30 -q",
            "preset_deep": "{cmd} dir -u {target} -x php,html,js,json,bak,zip -t 50",
            "preset": "{cmd} dir -u {target} -t 25"
        },
        {
            "name": "FFuF",
            "cmd": "ffuf",
            "desc": "Ultra-fast flexible web fuzzer written in Go for paths and parameters",
            "install": "go install github.com/ffuf/ffuf/v2@latest",
            "pip_pkg": None,
            "preset_quick": "{cmd} -u {target}/FUZZ -mc 200,301,302",
            "preset_deep": "{cmd} -u {target}/FUZZ -e .php,.html,.js,.json,.env,.bak -mc all -fc 404",
            "preset": "{cmd} -u {target}/FUZZ"
        },
        {
            "name": "Dirsearch",
            "cmd": "dirsearch",
            "desc": "Advanced command-line tool designed to brute force directories and files",
            "install": "pip install dirsearch",
            "pip_pkg": "dirsearch",
            "preset_quick": "{cmd} -u {target} -t 20",
            "preset_deep": "{cmd} -u {target} -e php,html,js,json,sql,bak,zip,env -t 40 --full-url",
            "preset": "{cmd} -u {target}"
        },
        {
            "name": "Feroxbuster",
            "cmd": "feroxbuster",
            "desc": "Fast, simple, recursive content discovery tool written in Rust",
            "install": "cargo install feroxbuster or winget install epi052.feroxbuster",
            "pip_pkg": None,
            "preset_quick": "{cmd} -u {target} -d 1",
            "preset_deep": "{cmd} -u {target} -d 3 -x php,js,json,bak",
            "preset": "{cmd} -u {target}"
        }
    ],
    "5. Database & SQL Injection Auditing": [
        {
            "name": "SQLmap",
            "cmd": "sqlmap",
            "desc": "Automatic SQL injection detection, fingerprinting, and database takeover tool",
            "install": "pip install sqlmap",
            "pip_pkg": "sqlmap",
            "preset_quick": "{cmd} -u {target} --batch --banner",
            "preset_deep": "{cmd} -u {target} --batch --dbs --level=3 --risk=2",
            "preset": "{cmd} -u {target} --batch --banner"
        },
        {
            "name": "Ghauri",
            "cmd": "ghauri",
            "desc": "Cross-platform advanced SQL injection detection and extraction tool",
            "install": "pip install ghauri",
            "pip_pkg": "ghauri",
            "preset_quick": "{cmd} -u {target} --batch",
            "preset_deep": "{cmd} -u {target} --dbs --batch --level=3",
            "preset": "{cmd} -u {target} --dbs"
        }
    ],
    "6. OSINT & Subdomain Intelligence": [
        {
            "name": "Sublist3r",
            "cmd": "sublist3r",
            "desc": "Fast subdomains enumeration tool using public search engines & OSINT",
            "install": "pip install sublist3r",
            "pip_pkg": "sublist3r",
            "preset_quick": "{cmd} -d {target} -t 20",
            "preset_deep": "{cmd} -d {target} -b -t 50",
            "preset": "{cmd} -d {target}"
        },
        {
            "name": "WhatWeb",
            "cmd": "whatweb",
            "desc": "Identifies websites technologies, content management systems, versions & headers",
            "install": "sudo apt install whatweb or gem install whatweb",
            "pip_pkg": None,
            "preset_quick": "{cmd} -a 1 {target}",
            "preset_deep": "{cmd} -v -a 3 {target}",
            "preset": "{cmd} -v -a 3 {target}"
        },
        {
            "name": "Whois",
            "cmd": "whois",
            "desc": "Client for the WHOIS domain registration and ASN directory service",
            "install": "winget install whois or sudo apt install whois",
            "pip_pkg": None,
            "preset_quick": "{cmd} {target}",
            "preset_deep": "{cmd} -H {target}",
            "preset": "{cmd} {target}"
        },
        {
            "name": "theHarvester",
            "cmd": "theHarvester",
            "desc": "Gather emails, subdomains, hosts, employee names, and open ports from OSINT",
            "install": "pip install theHarvester or git clone https://github.com/laramies/theHarvester",
            "pip_pkg": "theHarvester",
            "preset_quick": "{cmd} -d {target} -b google",
            "preset_deep": "{cmd} -d {target} -b all -l 300",
            "preset": "{cmd} -d {target} -b google,bing,crtsh"
        }
    ],
    "7. DNS & Infrastructure Enumeration": [
        {
            "name": "Dnsrecon",
            "cmd": "dnsrecon",
            "desc": "DNS enumeration and network reconnaissance script",
            "install": "pip install dnsrecon",
            "pip_pkg": "dnsrecon",
            "preset_quick": "{cmd} -d {target} -t std",
            "preset_deep": "{cmd} -d {target} -t axfr,zonewalk,bing",
            "preset": "{cmd} -d {target} -t std"
        },
        {
            "name": "Dnsenum",
            "cmd": "dnsenum",
            "desc": "Multithreaded perl script to enumerate DNS information and discover non-contiguous ip blocks",
            "install": "sudo apt install dnsenum",
            "pip_pkg": None,
            "preset_quick": "{cmd} {target}",
            "preset_deep": "{cmd} --enum {target}",
            "preset": "{cmd} {target}"
        }
    ],
    "8. SSL / TLS Security & Cipher Auditing": [
        {
            "name": "testssl.sh",
            "cmd": "testssl.sh",
            "desc": "Testing TLS/SSL encryption anywhere on any port for obsolete ciphers and flaws",
            "install": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git",
            "pip_pkg": None,
            "preset_quick": "{cmd} --fast {target}",
            "preset_deep": "{cmd} --full {target}",
            "preset": "{cmd} {target}"
        },
        {
            "name": "SSLyze",
            "cmd": "sslyze",
            "desc": "Fast and powerful SSL/TLS server scanning library analyzing certificate chain and ciphers",
            "install": "pip install sslyze",
            "pip_pkg": "sslyze",
            "preset_quick": "{cmd} {target}",
            "preset_deep": "{cmd} --regular {target}",
            "preset": "{cmd} {target}"
        }
    ],
    "9. Secrets & Repository Intelligence": [
        {
            "name": "TruffleHog",
            "cmd": "trufflehog",
            "desc": "Finds credentials and sensitive API keys leaked in codebases and web git directories",
            "install": "pip install trufflehog or brew install trufflehog",
            "pip_pkg": "trufflehog",
            "preset_quick": "{cmd} git {target} --depth 1",
            "preset_deep": "{cmd} git {target} --entropy=True",
            "preset": "{cmd} git {target}"
        }
    ],
    "10. Web Parameter & Route Spidering": [
        {
            "name": "ParamSpider",
            "cmd": "paramspider",
            "desc": "Mining parameters from dark corners of Web Archives for injection testing",
            "install": "pip install paramspider or git clone https://github.com/devanshbatham/paramspider",
            "pip_pkg": "paramspider",
            "preset_quick": "{cmd} -d {target}",
            "preset_deep": "{cmd} -d {target} --level high",
            "preset": "{cmd} -d {target}"
        }
    ]
}


class ToolArsenal:
    """Manages, installs, and launches external security tools with logging and summaries"""

    @staticmethod
    def get_tool_status(cmd: str) -> bool:
        """Check if command is in system PATH"""
        return shutil.which(cmd) is not None

    @staticmethod
    def get_all_tools() -> List[Dict[str, Any]]:
        """Flatten and enrich tool list with installation status"""
        tools = []
        for cat, items in ARSENAL_CATEGORIES.items():
            for item in items:
                entry = dict(item)
                entry["category"] = cat
                entry["installed"] = ToolArsenal.get_tool_status(entry["cmd"])
                tools.append(entry)
        return tools

    @classmethod
    def install_tool(cls, tool: Dict[str, Any]) -> bool:
        """Attempt automated installation of tool via pip or system package manager"""
        pip_pkg = tool.get("pip_pkg")
        if pip_pkg:
            print(f"[*] Installing '{tool['name']}' via pip into active environment...")
            try:
                res = subprocess.run([sys.executable, "-m", "pip", "install", pip_pkg], check=True)
                if res.returncode == 0:
                    print(f"[+] Successfully installed '{tool['name']}'!")
                    return True
            except Exception as e:
                print(f"[!] Pip installation failed: {e}")
                return False

        # Fallback to system instructions
        print(f"[!] Automatic installation not available for '{tool['name']}'.")
        print(f"[*] Recommended command: {tool['install']}")
        return False

    @classmethod
    def execute_tool(
        cls,
        tool: Dict[str, Any],
        target: str,
        mode: str = "standard",
        custom_args: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute tool with:
        1. Live terminal streaming.
        2. Automatic capture into ./reports/tools/<tool>_<target>_<timestamp>.log.
        3. Elapsed execution timing.
        """
        # Determine command template
        if custom_args:
            cmd_str = f"{tool['cmd']} {custom_args}"
        elif mode == "quick" and tool.get("preset_quick"):
            cmd_str = tool["preset_quick"].format(cmd=tool["cmd"], target=target)
        elif mode == "deep" and tool.get("preset_deep"):
            cmd_str = tool["preset_deep"].format(cmd=tool["cmd"], target=target)
        else:
            cmd_str = tool["preset"].format(cmd=tool["cmd"], target=target)

        # Clean target for filename
        clean_t = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_dir = Path("reports") / "tools"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"{tool['cmd']}_{clean_t}_{timestamp}.log"

        print(f"\n[*] Launching Tool: {tool['name']}")
        print(f"[*] Command: {cmd_str}")
        print(f"[*] Evidence Log: {log_file}\n" + "─" * 60 + "\n")

        start_time = time.time()
        output_lines = []

        try:
            process = subprocess.Popen(
                cmd_str,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace"
            )

            with log_file.open("w", encoding="utf-8") as lf:
                lf.write(f"=== SentinelAI Tool Execution Log ===\n")
                lf.write(f"Tool: {tool['name']}\n")
                lf.write(f"Command: {cmd_str}\n")
                lf.write(f"Started: {datetime.now().isoformat()}\n")
                lf.write("=" * 40 + "\n\n")

                if process.stdout:
                    for line in process.stdout:
                        sys.stdout.write(line)
                        sys.stdout.flush()
                        lf.write(line)
                        output_lines.append(line)

            process.wait()
            elapsed = time.time() - start_time
            print("\n" + "─" * 60)
            print(f"[+] {tool['name']} finished in {elapsed:.1f}s (Exit code: {process.returncode})")
            print(f"[+] Full execution output saved: {log_file.resolve()}")

            return {
                "tool": tool["name"],
                "command": cmd_str,
                "exit_code": process.returncode,
                "elapsed_seconds": elapsed,
                "log_file": str(log_file.resolve()),
                "output": "".join(output_lines)
            }
        except Exception as e:
            print(f"\n[!] Execution error: {e}")
            return {
                "tool": tool["name"],
                "command": cmd_str,
                "error": str(e)
            }
