"""
Curated Security Tools Arsenal & High-Efficiency Launcher
Cross-Platform Architecture (Windows, Linux, macOS) featuring:
1. Native Windows Package Manager (winget), Chocolatey & Pip integration.
2. Smart multi-path executable resolution across PATH, venv Scripts, and Program Files.
3. Live output logging, elapsed timing, and report integration.
"""
import shutil
import subprocess
import sys
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

IS_WINDOWS = sys.platform == "win32"

ARSENAL_CATEGORIES: Dict[str, List[Dict[str, Any]]] = {
    "1. Network Discovery & Port Auditing": [
        {
            "name": "Nmap",
            "cmd": "nmap",
            "desc": "Network exploration tool, service version detection & security scanner",
            "install_win": "winget install Insecure.Nmap or choco install nmap",
            "install_linux": "sudo apt install nmap or sudo pacman -S nmap",
            "install": "winget install Insecure.Nmap (Windows) or sudo apt install nmap (Linux)",
            "winget_id": "Insecure.Nmap",
            "choco_pkg": "nmap",
            "pip_pkg": None,
            "preset_quick": "{cmd} -F -Pn {target}",
            "preset_deep": "{cmd} -sV -sC -Pn -T4 {target}",
            "preset": "{cmd} -sV -sC -Pn {target}"
        },
        {
            "name": "RustScan",
            "cmd": "rustscan",
            "desc": "Modern port scanner with ultra-fast asynchronous SYN scanning",
            "install_win": "winget install rustscan or cargo install rustscan",
            "install_linux": "cargo install rustscan or sudo apt install rustscan",
            "install": "cargo install rustscan or winget install rustscan",
            "winget_id": "rustscan",
            "choco_pkg": "rustscan",
            "pip_pkg": None,
            "preset_quick": "{cmd} -a {target} --range 1-1000",
            "preset_deep": "{cmd} -a {target} --ulimit 5000 -- -sV",
            "preset": "{cmd} -a {target} --ulimit 5000"
        },
        {
            "name": "Masscan",
            "cmd": "masscan",
            "desc": "High-volume TCP port scanner capable of scanning entire networks",
            "install_win": "choco install masscan or download precompiled Windows binary",
            "install_linux": "sudo apt install masscan",
            "install": "choco install masscan (Windows) or sudo apt install masscan (Linux)",
            "winget_id": None,
            "choco_pkg": "masscan",
            "pip_pkg": None,
            "preset_quick": "{cmd} {target} -p80,443,8080,8443 --rate=1000",
            "preset_deep": "{cmd} {target} -p1-65535 --rate=2000",
            "preset": "{cmd} {target} -p1-65535 --rate=1000"
        },
        {
            "name": "Netcat (nc / ncat)",
            "cmd": "nc",
            "desc": "Arbitrary TCP and UDP port connections, banner grabbing, and port listening",
            "install_win": "ncat via Nmap (winget install Insecure.Nmap) or choco install netcat",
            "install_linux": "sudo apt install netcat or sudo apt install ncat",
            "install": "ncat via nmap or sudo apt install netcat",
            "winget_id": "Insecure.Nmap",
            "choco_pkg": "netcat",
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
            "install_win": "choco install nikto or scoop install nikto",
            "install_linux": "sudo apt install nikto",
            "install": "choco install nikto (Windows) or sudo apt install nikto (Linux)",
            "winget_id": None,
            "choco_pkg": "nikto",
            "pip_pkg": None,
            "preset_quick": "{cmd} -h {target} -Tuning 1,2",
            "preset_deep": "{cmd} -h {target} -C all",
            "preset": "{cmd} -h {target}"
        },
        {
            "name": "Nuclei",
            "cmd": "nuclei",
            "desc": "Fast and customizable vulnerability scanner based on community YAML templates",
            "install_win": "winget install projectdiscovery.nuclei or scoop install nuclei",
            "install_linux": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "install": "winget install projectdiscovery.nuclei or go install nuclei",
            "winget_id": "projectdiscovery.nuclei",
            "choco_pkg": "nuclei",
            "pip_pkg": None,
            "preset_quick": "{cmd} -u {target} -t cves/ -severity critical,high",
            "preset_deep": "{cmd} -u {target} -severity critical,high,medium,low",
            "preset": "{cmd} -u {target} -severity critical,high,medium"
        },
        {
            "name": "Wapiti",
            "cmd": "wapiti",
            "desc": "Web application vulnerability scanner (audits XSS, SQLi, SSRF, XXE)",
            "install_win": "pip install wapiti3",
            "install_linux": "pip install wapiti3 or sudo apt install wapiti",
            "install": "pip install wapiti3",
            "winget_id": None,
            "choco_pkg": None,
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
            "install_win": "docker run --rm wpscanteam/wpscan or gem install wpscan",
            "install_linux": "sudo apt install wpscan or gem install wpscan",
            "install": "gem install wpscan or docker run --rm wpscanteam/wpscan",
            "winget_id": None,
            "choco_pkg": None,
            "pip_pkg": None,
            "preset_quick": "{cmd} --url {target} --enumerate p",
            "preset_deep": "{cmd} --url {target} --enumerate vp,vt,tt,cb,dps,u",
            "preset": "{cmd} --url {target} --enumerate vp,vt,tt,cb,dps,u"
        },
        {
            "name": "CMSmap",
            "cmd": "cmsmap",
            "desc": "Python open-source CMS scanner for WordPress, Joomla, Drupal, and Moodle",
            "install_win": "pip install cmsmap",
            "install_linux": "pip install cmsmap or git clone https://github.com/Dionach/CMSmap.git",
            "install": "pip install cmsmap",
            "winget_id": None,
            "choco_pkg": None,
            "pip_pkg": "cmsmap",
            "preset_quick": "{cmd} {target} -f W",
            "preset_deep": "{cmd} {target} -a",
            "preset": "{cmd} {target}"
        },
        {
            "name": "Droopescan",
            "cmd": "droopescan",
            "desc": "Plugin-based scanner for Drupal, Silverstripe, and WordPress",
            "install_win": "pip install droopescan",
            "install_linux": "pip install droopescan",
            "install": "pip install droopescan",
            "winget_id": None,
            "choco_pkg": None,
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
            "install_win": "scoop install gobuster or choco install gobuster or go install github.com/OJ/gobuster/v3@latest",
            "install_linux": "go install github.com/OJ/gobuster/v3@latest or sudo apt install gobuster",
            "install": "go install github.com/OJ/gobuster/v3@latest",
            "winget_id": None,
            "choco_pkg": "gobuster",
            "pip_pkg": None,
            "preset_quick": "{cmd} dir -u {target} -t 30 -q",
            "preset_deep": "{cmd} dir -u {target} -x php,html,js,json,bak,zip -t 50",
            "preset": "{cmd} dir -u {target} -t 25"
        },
        {
            "name": "FFuF",
            "cmd": "ffuf",
            "desc": "Ultra-fast flexible web fuzzer written in Go for paths and parameters",
            "install_win": "choco install ffuf or scoop install ffuf or go install github.com/ffuf/ffuf/v2@latest",
            "install_linux": "go install github.com/ffuf/ffuf/v2@latest or sudo apt install ffuf",
            "install": "go install github.com/ffuf/ffuf/v2@latest",
            "winget_id": None,
            "choco_pkg": "ffuf",
            "pip_pkg": None,
            "preset_quick": "{cmd} -u {target}/FUZZ -mc 200,301,302",
            "preset_deep": "{cmd} -u {target}/FUZZ -e .php,.html,.js,.json,.env,.bak -mc all -fc 404",
            "preset": "{cmd} -u {target}/FUZZ"
        },
        {
            "name": "Dirsearch",
            "cmd": "dirsearch",
            "desc": "Advanced command-line tool designed to brute force directories and files",
            "install_win": "pip install dirsearch",
            "install_linux": "pip install dirsearch",
            "install": "pip install dirsearch",
            "winget_id": None,
            "choco_pkg": None,
            "pip_pkg": "dirsearch",
            "preset_quick": "{cmd} -u {target} -t 20",
            "preset_deep": "{cmd} -u {target} -e php,html,js,json,sql,bak,zip,env -t 40 --full-url",
            "preset": "{cmd} -u {target}"
        },
        {
            "name": "Feroxbuster",
            "cmd": "feroxbuster",
            "desc": "Fast, simple, recursive content discovery tool written in Rust",
            "install_win": "winget install epi052.feroxbuster or choco install feroxbuster",
            "install_linux": "cargo install feroxbuster or sudo apt install feroxbuster",
            "install": "cargo install feroxbuster or winget install epi052.feroxbuster",
            "winget_id": "epi052.feroxbuster",
            "choco_pkg": "feroxbuster",
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
            "install_win": "pip install sqlmap or choco install sqlmap",
            "install_linux": "pip install sqlmap or sudo apt install sqlmap",
            "install": "pip install sqlmap",
            "winget_id": None,
            "choco_pkg": "sqlmap",
            "pip_pkg": "sqlmap",
            "preset_quick": "{cmd} -u {target} --batch --banner",
            "preset_deep": "{cmd} -u {target} --batch --dbs --level=3 --risk=2",
            "preset": "{cmd} -u {target} --batch --banner"
        },
        {
            "name": "Ghauri",
            "cmd": "ghauri",
            "desc": "Cross-platform advanced SQL injection detection and extraction tool",
            "install_win": "pip install ghauri",
            "install_linux": "pip install ghauri",
            "install": "pip install ghauri",
            "winget_id": None,
            "choco_pkg": None,
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
            "install_win": "pip install sublist3r",
            "install_linux": "pip install sublist3r or sudo apt install sublist3r",
            "install": "pip install sublist3r",
            "winget_id": None,
            "choco_pkg": None,
            "pip_pkg": "sublist3r",
            "preset_quick": "{cmd} -d {target} -t 20",
            "preset_deep": "{cmd} -d {target} -b -t 50",
            "preset": "{cmd} -d {target}"
        },
        {
            "name": "WhatWeb",
            "cmd": "whatweb",
            "desc": "Identifies websites technologies, content management systems, versions & headers",
            "install_win": "gem install whatweb or run in WSL/Docker",
            "install_linux": "sudo apt install whatweb or gem install whatweb",
            "install": "sudo apt install whatweb or gem install whatweb",
            "winget_id": None,
            "choco_pkg": None,
            "pip_pkg": None,
            "preset_quick": "{cmd} -a 1 {target}",
            "preset_deep": "{cmd} -v -a 3 {target}",
            "preset": "{cmd} -v -a 3 {target}"
        },
        {
            "name": "Whois",
            "cmd": "whois",
            "desc": "Client for the WHOIS domain registration and ASN directory service",
            "install_win": "winget install whois or choco install whois",
            "install_linux": "sudo apt install whois",
            "install": "winget install whois or sudo apt install whois",
            "winget_id": "whois",
            "choco_pkg": "whois",
            "pip_pkg": None,
            "preset_quick": "{cmd} {target}",
            "preset_deep": "{cmd} -H {target}",
            "preset": "{cmd} {target}"
        },
        {
            "name": "theHarvester",
            "cmd": "theHarvester",
            "desc": "Gather emails, subdomains, hosts, employee names, and open ports from OSINT",
            "install_win": "pip install theHarvester",
            "install_linux": "pip install theHarvester or sudo apt install theharvester",
            "install": "pip install theHarvester",
            "winget_id": None,
            "choco_pkg": None,
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
            "install_win": "pip install dnsrecon",
            "install_linux": "pip install dnsrecon or sudo apt install dnsrecon",
            "install": "pip install dnsrecon",
            "winget_id": None,
            "choco_pkg": None,
            "pip_pkg": "dnsrecon",
            "preset_quick": "{cmd} -d {target} -t std",
            "preset_deep": "{cmd} -d {target} -t axfr,zonewalk,bing",
            "preset": "{cmd} -d {target} -t std"
        },
        {
            "name": "Dnsenum",
            "cmd": "dnsenum",
            "desc": "Multithreaded perl script to enumerate DNS information and discover IP blocks",
            "install_win": "Run in WSL, or use Dnsrecon natively on Windows",
            "install_linux": "sudo apt install dnsenum",
            "install": "sudo apt install dnsenum",
            "winget_id": None,
            "choco_pkg": None,
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
            "desc": "Testing TLS/SSL encryption for obsolete ciphers (On Windows: run via WSL/Git-Bash, or use SSLyze)",
            "install_win": "Run via WSL/Git-Bash, or use SSLyze natively on Windows",
            "install_linux": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git",
            "install": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git",
            "winget_id": None,
            "choco_pkg": None,
            "pip_pkg": None,
            "preset_quick": "{cmd} --fast {target}",
            "preset_deep": "{cmd} --full {target}",
            "preset": "{cmd} {target}"
        },
        {
            "name": "SSLyze",
            "cmd": "sslyze",
            "desc": "Fast and powerful SSL/TLS server scanning library analyzing certificate chains and ciphers",
            "install_win": "pip install sslyze",
            "install_linux": "pip install sslyze",
            "install": "pip install sslyze",
            "winget_id": None,
            "choco_pkg": None,
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
            "desc": "Finds credentials and sensitive API keys leaked in codebases and git repositories",
            "install_win": "winget install trufflesecurity.trufflehog or pip install trufflehog",
            "install_linux": "pip install trufflehog or brew install trufflehog",
            "install": "winget install trufflesecurity.trufflehog or pip install trufflehog",
            "winget_id": "trufflesecurity.trufflehog",
            "choco_pkg": None,
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
            "install_win": "pip install paramspider or git clone https://github.com/devanshbatham/paramspider",
            "install_linux": "pip install paramspider or git clone https://github.com/devanshbatham/paramspider",
            "install": "pip install paramspider",
            "winget_id": None,
            "choco_pkg": None,
            "pip_pkg": "paramspider",
            "preset_quick": "{cmd} -d {target}",
            "preset_deep": "{cmd} -d {target} --level high",
            "preset": "{cmd} -d {target}"
        }
    ]
}


class ToolArsenal:
    """Manages, installs, and launches external security tools with Windows & Linux cross-platform intelligence"""

    @classmethod
    def find_tool_executable(cls, cmd: str) -> Optional[str]:
        """
        Intelligently locate executable across Windows, Linux, and macOS.
        Checks:
        1. System PATH.
        2. Active Python environment Scripts/ (e.g. .venv/Scripts on Windows).
        3. Standard Windows Program Files, Winget, Chocolatey, and Scoop locations.
        """
        # 1. Standard PATH lookup
        path = shutil.which(cmd)
        if path:
            return path

        # Windows-specific search logic
        if IS_WINDOWS:
            # Check with .exe if not provided
            if not cmd.lower().endswith(".exe"):
                path = shutil.which(f"{cmd}.exe")
                if path:
                    return path

            # 2. Check active Python environment Scripts directory
            venv_scripts = Path(sys.prefix) / "Scripts"
            for ext in [".exe", ".bat", ".cmd", ".py", ""]:
                cand = venv_scripts / f"{cmd}{ext}"
                if cand.is_file():
                    return str(cand.resolve())

            # Check Python executable parent folder
            py_parent = Path(sys.executable).parent
            for ext in [".exe", ".bat", ".cmd", ".py", ""]:
                cand = py_parent / f"{cmd}{ext}"
                if cand.is_file():
                    return str(cand.resolve())

            # 3. Check common Windows installation paths
            common_windows_locations = [
                Path(os.environ.get("ProgramFiles", "C:\\Program Files")),
                Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")),
                Path(os.environ.get("LOCALAPPDATA", "")) / "Programs",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links",
                Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "chocolatey" / "bin",
                Path.home() / "scoop" / "shims",
            ]

            tool_subfolders = {
                "nmap": ["Nmap", "nmap"],
                "nc": ["Nmap", "ncat", "netcat"],
                "ncat": ["Nmap"],
                "nikto": ["nikto"],
                "masscan": ["masscan"],
                "rustscan": ["rustscan"],
                "nuclei": ["nuclei", "projectdiscovery"],
                "feroxbuster": ["feroxbuster"],
                "trufflehog": ["trufflehog"],
                "whois": ["whois"],
            }

            search_names = [f"{cmd}.exe", f"{cmd}.bat", f"{cmd}.cmd", f"{cmd}"]
            if cmd == "nc":
                search_names.extend(["ncat.exe", "ncat"])

            for base in common_windows_locations:
                if not base or not base.exists():
                    continue
                # Direct check
                for sname in search_names:
                    direct = base / sname
                    if direct.is_file():
                        return str(direct.resolve())
                # Subfolder check
                subdirs = tool_subfolders.get(cmd.lower(), [cmd.lower()])
                for sdir in subdirs:
                    sub_path = base / sdir
                    if sub_path.exists():
                        for sname in search_names:
                            cand = sub_path / sname
                            if cand.is_file():
                                return str(cand.resolve())

        return None

    @classmethod
    def get_tool_status(cls, cmd: str) -> bool:
        """Check if command is in system PATH or resolved locally"""
        return cls.find_tool_executable(cmd) is not None

    @classmethod
    def get_all_tools(cls) -> List[Dict[str, Any]]:
        """Flatten and enrich tool list with installation status and resolved path"""
        tools = []
        for cat, items in ARSENAL_CATEGORIES.items():
            for item in items:
                entry = dict(item)
                entry["category"] = cat
                exe = cls.find_tool_executable(entry["cmd"])
                entry["installed"] = exe is not None
                entry["resolved_path"] = exe
                tools.append(entry)
        return tools

    @classmethod
    def install_tool(cls, tool: Dict[str, Any], method: str = "auto") -> bool:
        """
        Attempt automated installation via pip, winget, or choco on Windows,
        or pip / package manager on Linux.
        """
        pip_pkg = tool.get("pip_pkg")
        winget_id = tool.get("winget_id")
        choco_pkg = tool.get("choco_pkg")

        # 1. Pip install (Cross-Platform)
        if (method in ("auto", "pip")) and pip_pkg:
            print(f"[*] Installing '{tool['name']}' via pip into active Python environment...")
            try:
                res = subprocess.run([sys.executable, "-m", "pip", "install", pip_pkg])
                if res.returncode == 0:
                    print(f"[+] Successfully installed '{tool['name']}' via pip!")
                    return True
            except Exception as e:
                print(f"[!] Pip installation failed: {e}")
                if method == "pip":
                    return False

        # 2. Windows Package Manager (winget)
        if IS_WINDOWS and (method in ("auto", "winget")) and winget_id:
            winget_path = shutil.which("winget")
            if winget_path:
                print(f"[*] Installing '{tool['name']}' via Windows Package Manager (winget: {winget_id})...")
                try:
                    res = subprocess.run(
                        f'winget install --id {winget_id} -e --accept-package-agreements --accept-source-agreements',
                        shell=True
                    )
                    if res.returncode == 0:
                        print(f"[+] Successfully installed '{tool['name']}' via winget!")
                        return True
                except Exception as e:
                    print(f"[!] winget installation failed: {e}")
                    if method == "winget":
                        return False

        # 3. Chocolatey (choco) on Windows
        if IS_WINDOWS and (method in ("auto", "choco")) and choco_pkg:
            choco_path = shutil.which("choco")
            if choco_path:
                print(f"[*] Installing '{tool['name']}' via Chocolatey (choco: {choco_pkg})...")
                try:
                    res = subprocess.run(f"choco install {choco_pkg} -y", shell=True)
                    if res.returncode == 0:
                        print(f"[+] Successfully installed '{tool['name']}' via choco!")
                        return True
                except Exception as e:
                    print(f"[!] choco installation failed: {e}")
                    if method == "choco":
                        return False

        # Fallback guidance
        guide = tool.get("install_win" if IS_WINDOWS else "install_linux", tool.get("install"))
        print(f"[!] Automated installation not available for '{tool['name']}'.")
        print(f"[*] Recommended command: {guide}")
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
        Execute tool with live streaming and structured evidence logging.
        Handles Windows paths with spaces and script extension execution.
        """
        # Resolve executable
        exe_path = cls.find_tool_executable(tool["cmd"]) or tool["cmd"]
        if " " in exe_path and not exe_path.startswith('"'):
            exe_cmd = f'"{exe_path}"'
        else:
            exe_cmd = exe_path

        # Determine command template
        if custom_args:
            cmd_str = f"{exe_cmd} {custom_args}"
        elif mode == "quick" and tool.get("preset_quick"):
            cmd_str = tool["preset_quick"].format(cmd=exe_cmd, target=target)
        elif mode == "deep" and tool.get("preset_deep"):
            cmd_str = tool["preset_deep"].format(cmd=exe_cmd, target=target)
        else:
            cmd_str = tool["preset"].format(cmd=exe_cmd, target=target)

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
