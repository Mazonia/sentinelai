"""
High-Performance Asynchronous Directory & Sensitive File Fuzzer
Built-in directory busting engine with wildcard 404 detection.
"""
import asyncio
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

from ..core.http_client import AsyncHTTPClient

logger = logging.getLogger(__name__)

COMMON_PATHS = [
    # Admin & Management
    "/admin", "/admin/", "/administrator", "/admin/login", "/dashboard",
    "/controlpanel", "/cpanel", "/panel", "/console", "/manage", "/manager",
    # Sensitive Configs & Source Code
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/HEAD", "/.git/config", "/.gitignore", "/.svn/entries",
    "/config.json", "/configuration.json", "/config.php", "/config.yml",
    "/settings.py", "/database.yml", "/credentials.json",
    # Backups & Dumps
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql", "/db.sql",
    "/database.sql", "/site-backup.zip", "/www.zip", "/backup/",
    # Info & Debugging
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/phpinfo.php", "/info.php", "/test.php", "/debug", "/server-status",
    "/actuator", "/actuator/health", "/actuator/env",
    # API & Documentation
    "/api", "/api/v1", "/api/v2", "/graphql",
    "/swagger.json", "/openapi.json", "/swagger-ui.html", "/docs", "/api/docs",
    # CMS Specific
    "/wp-admin", "/wp-login.php", "/wp-content", "/xmlrpc.php",
    "/administrator/index.php", "/user/login",
]


class DirFuzzer:
    """
    Asynchronous Directory and Sensitive File Fuzzer
    """

    def __init__(self, http_client: AsyncHTTPClient, concurrency: int = 25):
        self.http_client = http_client
        self.concurrency = concurrency
        self.findings = []

    async def scan(
        self,
        urls: List[str],
        intensity: str = "medium",
        custom_wordlist: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Run directory fuzzing against target base URLs"""
        self.findings = []
        if not urls:
            return []

        base_url = urls[0]
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        wordlist = custom_wordlist or COMMON_PATHS
        if intensity == "low":
            wordlist = wordlist[:20]

        logger.info(f"Fuzzing {len(wordlist)} paths on {origin}")

        # Check for wildcard 404 response
        wildcard_len = await self._check_wildcard(origin)

        sem = asyncio.Semaphore(self.concurrency)

        async def _probe(path: str):
            async with sem:
                target_url = urljoin(origin, path)
                try:
                    resp = await self.http_client.get(target_url, allow_redirects=False)
                    if not resp:
                        return

                    status = resp.status
                    body = await resp.read()
                    length = len(body)
                    ctype = resp.headers.get("Content-Type", "")

                    # Filter standard 404 and wildcard false positives
                    if status in [200, 201, 301, 302, 307, 308, 401, 403]:
                        if wildcard_len is not None and abs(length - wildcard_len) < 50:
                            return  # Wildcard soft-404 match

                        severity = "HIGH" if any(p in path for p in [".env", ".git", ".sql", "backup"]) else ("MEDIUM" if status in [200, 403] else "LOW")
                        self.findings.append({
                            "type": "discovered_sensitive_resource",
                            "severity": severity,
                            "title": f"Sensitive Resource Discovered ({path})",
                            "url": target_url,
                            "parameter": path,
                            "evidence": f"HTTP {status} - Content-Length: {length} - Type: {ctype}",
                            "description": f"Accessible path identified during fuzzing: {path} (HTTP {status})",
                            "remediation": f"Restrict access to '{path}' via web server configuration or remove publicly exposed sensitive artifacts.",
                            "cvss_score": 7.5 if severity == "HIGH" else (5.3 if severity == "MEDIUM" else 3.1)
                        })
                except Exception:
                    pass

        await asyncio.gather(*[_probe(p) for p in wordlist], return_exceptions=True)
        return self.findings

    async def _check_wildcard(self, origin: str) -> Optional[int]:
        """Check if server returns 200 with static page for random non-existent URL"""
        random_path = "/sentinel_wildcard_probe_4982174"
        try:
            resp = await self.http_client.get(urljoin(origin, random_path), allow_redirects=False)
            if resp and resp.status == 200:
                body = await resp.read()
                return len(body)
        except Exception:
            pass
        return None
