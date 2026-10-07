"""
Curated Security Tools Arsenal & Launcher
Inspired by hackingtool, featuring automated environment detection & launchers.
"""
import shutil
import subprocess
import sys
from typing import Dict, List, Any

ARSENAL_CATEGORIES: Dict[str, List[Dict[str, Any]]] = {
    "1. Network & Port Scanning": [
        {
            "name": "Nmap",
            "cmd": "nmap",
            "desc": "Network exploration tool and security / port scanner",
            "install": "winget install Insecure.Nmap (Windows) or sudo apt install nmap (Linux)",
            "preset": "{cmd} -sV -sC -Pn {target}"
        },
        {
            "name": "RustScan",
            "cmd": "rustscan",
            "desc": "Modern port scanner with ultra-fast SYN scanning",
            "install": "cargo install rustscan or brew install rustscan",
            "preset": "{cmd} -a {target} --ulimit 5000"
        },
        {
            "name": "Masscan",
            "cmd": "masscan",
            "desc": "Mass IP port scanner, TCP port scanner",
            "install": "sudo apt install masscan",
            "preset": "{cmd} {target} -p1-65535 --rate=1000"
        }
    ],
    "2. Web Vulnerability Scanning": [
        {
            "name": "Nikto",
            "cmd": "nikto",
            "desc": "Comprehensive web server scanner for dangerous files & CGIs",
            "install": "sudo apt install nikto or git clone https://github.com/sullo/nikto",
            "preset": "{cmd} -h {target}"
        },
        {
            "name": "Nuclei",
            "cmd": "nuclei",
            "desc": "Fast and customizable vulnerability scanner based on simple YAML DSL",
            "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "preset": "{cmd} -u {target} -severity critical,high,medium"
        },
        {
            "name": "Wapiti",
            "cmd": "wapiti",
            "desc": "Web application vulnerability scanner (black-box)",
            "install": "pip install wapiti3",
            "preset": "{cmd} -u {target} --flush-session"
        },
        {
            "name": "WPScan",
            "cmd": "wpscan",
            "desc": "Black box WordPress vulnerability scanner",
            "install": "gem install wpscan",
            "preset": "{cmd} --url {target} --enumerate vp,vt,tt,cb,dps,u"
        }
    ],
    "3. Directory & Content Fuzzing": [
        {
            "name": "Gobuster",
            "cmd": "gobuster",
            "desc": "Directory/file, DNS and VHost busting tool written in Go",
            "install": "go install github.com/OJ/gobuster/v3@latest",
            "preset": "{cmd} dir -u {target} -w common.txt"
        },
        {
            "name": "FFuF",
            "cmd": "ffuf",
            "desc": "Fast web fuzzer written in Go",
            "install": "go install github.com/ffuf/ffuf/v2@latest",
            "preset": "{cmd} -u {target}/FUZZ -w common.txt"
        },
        {
            "name": "Dirsearch",
            "cmd": "dirsearch",
            "desc": "Web path scanner for discovering hidden resources",
            "install": "pip install dirsearch",
            "preset": "{cmd} -u {target}"
        }
    ],
    "4. Database & Injection Auditing": [
        {
            "name": "SQLmap",
            "cmd": "sqlmap",
            "desc": "Automatic SQL injection and database takeover tool",
            "install": "pip install sqlmap or git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git",
            "preset": "{cmd} -u {target} --batch --banner"
        },
        {
            "name": "Ghauri",
            "cmd": "ghauri",
            "desc": "Advanced cross-platform SQL injection detection & exploitation tool",
            "install": "pip install ghauri",
            "preset": "{cmd} -u {target} --dbs"
        }
    ],
    "5. OSINT & Reconnaissance": [
        {
            "name": "Sublist3r",
            "cmd": "sublist3r",
            "desc": "Fast subdomains enumeration tool using OSINT",
            "install": "pip install sublist3r",
            "preset": "{cmd} -d {target}"
        },
        {
            "name": "WhatWeb",
            "cmd": "whatweb",
            "desc": "Next generation web scanner identifies technologies, CMS, versions",
            "install": "sudo apt install whatweb",
            "preset": "{cmd} -v -a 3 {target}"
        },
        {
            "name": "Whois",
            "cmd": "whois",
            "desc": "Client for the WHOIS directory service",
            "install": "sudo apt install whois",
            "preset": "{cmd} {target}"
        }
    ],
    "6. SSL / TLS Security": [
        {
            "name": "testssl.sh",
            "cmd": "testssl.sh",
            "desc": "Testing TLS/SSL encryption anywhere on any port",
            "install": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git",
            "preset": "{cmd} {target}"
        },
        {
            "name": "SSLyze",
            "cmd": "sslyze",
            "desc": "Fast and powerful SSL/TLS server scanning library",
            "install": "pip install sslyze",
            "preset": "{cmd} {target}"
        }
    ]
}


class ToolArsenal:
    """Manages and launches security tools with host availability check"""

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

    @staticmethod
    def execute_tool(tool: Dict[str, Any], target: str) -> None:
        """Launch selected tool with target substitution"""
        cmd_str = tool["preset"].format(cmd=tool["cmd"], target=target)
        print(f"\n[*] Launching: {cmd_str}\n")
        try:
            subprocess.run(cmd_str, shell=True)
        except Exception as e:
            print(f"[!] Error executing {tool['name']}: {e}")
