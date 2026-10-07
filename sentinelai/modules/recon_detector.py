"""
Reconnaissance, OSINT, and Technology Fingerprinting Module
"""
import asyncio
import socket
import ssl
import json
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import aiohttp

logger = logging.getLogger(__name__)

TOP_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
}

WAF_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status", "__cfduid"], "server": ["cloudflare"]},
    "AWS CloudFront / WAF": {"headers": ["x-amz-cf-id", "x-amz-request-id", "x-amzn-waf-action"], "server": ["cloudfront"]},
    "Akamai": {"headers": ["x-akamai-transformed", "akamai-origin-hop"], "server": ["akamai"]},
    "Imperva / Incapsula": {"headers": ["x-iinfo", "x-cdn"], "cookies": ["incap_ses", "visid_incap"]},
    "Sucuri": {"headers": ["x-sucuri-id", "x-sucuri-cache"], "server": ["sucuri"]},
    "ModSecurity": {"headers": ["mod_security", "no-cache"]},
    "F5 BIG-IP": {"headers": ["x-wa-info"], "cookies": ["bigipserver", "ts"]},
}

COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
    "portal", "ns", "ww1", "host", "support", "dev", "api", "beta",
    "admin", "app", "auth", "staging", "corp", "cdn", "internal"
]


class ReconDetector:
    """
    Advanced Reconnaissance, Port Scanning, WAF Detection, and Fingerprinting
    """

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def scan_domain(self, target: str) -> Dict[str, Any]:
        parsed = urlparse(target if "://" in target else f"http://{target}")
        hostname = parsed.hostname or target
        if ":" in hostname:
            hostname = hostname.split(":")[0]

        logger.info(f"Starting reconnaissance on {hostname}")
        results = {
            "target": target,
            "hostname": hostname,
            "ip_addresses": [],
            "open_ports": [],
            "subdomains": [],
            "technologies": [],
            "waf": None,
            "server_banner": None
        }

        ip_list = await self._resolve_ips(hostname)
        results["ip_addresses"] = ip_list
        primary_ip = ip_list[0] if ip_list else None

        if primary_ip:
            results["open_ports"] = await self._scan_ports(primary_ip)

        web_info = await self._fingerprint_web(target if "://" in target else f"https://{hostname}")
        results["technologies"] = web_info.get("technologies", [])
        results["waf"] = web_info.get("waf")
        results["server_banner"] = web_info.get("server")

        results["subdomains"] = await self._discover_subdomains(hostname)
        return results

    async def _resolve_ips(self, hostname: str) -> List[str]:
        loop = asyncio.get_running_loop()
        try:
            addr_info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            return sorted(list({info[4][0] for info in addr_info}))
        except Exception:
            return []

    async def _scan_ports(self, ip: str, ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        target_ports = ports or list(TOP_PORTS.keys())
        open_ports = []
        sem = asyncio.Semaphore(50)

        async def _check_port(port: int):
            async with sem:
                try:
                    conn = asyncio.open_connection(ip, port)
                    _, writer = await asyncio.wait_for(conn, timeout=1.5)
                    service = TOP_PORTS.get(port, "Unknown")
                    open_ports.append({"port": port, "service": service, "state": "open"})
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                except Exception:
                    pass

        await asyncio.gather(*[_check_port(p) for p in target_ports], return_exceptions=True)
        return sorted(open_ports, key=lambda x: x["port"])

    async def _fingerprint_web(self, url: str) -> Dict[str, Any]:
        technologies = set()
        waf = None
        server = "Unknown"

        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False, allow_redirects=True) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    server = headers.get("server", "Unknown")
                    if server != "Unknown":
                        technologies.add(f"Server: {server}")

                    if "x-powered-by" in headers:
                        technologies.add(f"Powered-By: {headers['x-powered-by']}")

                    for waf_name, rules in WAF_SIGNATURES.items():
                        if any(h in headers for h in rules.get("headers", [])):
                            waf = waf_name
                            break
                        if any(s in server.lower() for s in rules.get("server", [])):
                            waf = waf_name
                            break

                    text = (await resp.text(errors="ignore")).lower()
                    if "wp-content" in text or "wordpress" in text:
                        technologies.add("CMS: WordPress")
                    if "drupal" in text:
                        technologies.add("CMS: Drupal")
                    if "joomla" in text:
                        technologies.add("CMS: Joomla")
                    if "__next" in text or "next.js" in text:
                        technologies.add("Frontend: Next.js")
                    if "react" in text:
                        technologies.add("Frontend: React")
                    if "vue" in text or "vue.js" in text:
                        technologies.add("Frontend: Vue.js")
                    if "laravel" in text or "csrf-token" in text:
                        technologies.add("Backend: Laravel/PHP")
                    if "django" in text or "csrfmiddlewaretoken" in text:
                        technologies.add("Backend: Django/Python")
        except Exception:
            pass

        return {
            "technologies": sorted(list(technologies)),
            "waf": waf,
            "server": server
        }

    async def _discover_subdomains(self, domain: str) -> List[str]:
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            timeout = aiohttp.ClientTimeout(total=8)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            name = entry.get("name_value", "")
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if sub and "*" not in sub and sub.endswith(domain) and sub != domain:
                                    subdomains.add(sub)
        except Exception:
            pass

        if len(subdomains) < 5:
            loop = asyncio.get_running_loop()
            for prefix in COMMON_SUBDOMAINS:
                candidate = f"{prefix}.{domain}"
                try:
                    await loop.getaddrinfo(candidate, 80, family=socket.AF_INET)
                    subdomains.add(candidate)
                except Exception:
                    pass

        return sorted(list(subdomains))
