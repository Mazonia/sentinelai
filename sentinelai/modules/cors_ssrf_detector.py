"""
CORS Misconfiguration, SSRF, and Open Redirect Detection Module
"""
import asyncio
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..core.http_client import AsyncHTTPClient

logger = logging.getLogger(__name__)

REDIRECT_PARAMS = ["redirect", "url", "next", "return", "dest", "destination", "target", "r", "forward", "goto"]
SSRF_PARAMS = ["url", "dest", "feed", "webhook", "endpoint", "proxy", "fetch", "path", "api", "image", "src"]


class CORSSSRFDetector:
    """
    Detects Cross-Origin Resource Sharing (CORS) flaws, Open Redirects, and SSRF points.
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
        # Test CORS on unique domains/paths
        unique_paths = list(set(urls))[:10]
        for u in unique_paths:
            tasks.append(self._test_cors(u))
            tasks.append(self._test_open_redirect(u))
            tasks.append(self._test_ssrf_parameters(u))

        await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings

    async def _test_cors(self, url: str):
        """Test for insecure origin reflection & credential exposure"""
        test_origin = "https://evil-sentinel-attacker.com"
        headers = {"Origin": test_origin}

        try:
            resp = await self.http_client.get(url, headers=headers)
            if not resp:
                return

            acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

            if acao == test_origin:
                sev = "HIGH" if acac == "true" else "MEDIUM"
                self.findings.append({
                    "type": "cors_arbitrary_origin_reflection",
                    "severity": sev,
                    "title": "CORS Misconfiguration: Arbitrary Origin Reflection",
                    "url": url,
                    "parameter": "Origin header",
                    "evidence": f"Access-Control-Allow-Origin: {acao} | Access-Control-Allow-Credentials: {acac}",
                    "description": "Server dynamically reflects arbitrary untrusted Origin headers. If credentials are true, attackers can read authenticated responses cross-origin.",
                    "remediation": "Do not dynamically reflect Origin. Implement an explicit allowlist of trusted domains and omit credentials where possible.",
                    "cvss_score": 8.1 if sev == "HIGH" else 5.3
                })

            # Check null origin reflection
            null_headers = {"Origin": "null"}
            resp_null = await self.http_client.get(url, headers=null_headers)
            if resp_null and resp_null.headers.get("Access-Control-Allow-Origin", "").strip() == "null" and resp_null.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true":
                self.findings.append({
                    "type": "cors_null_origin_allowed",
                    "severity": "HIGH",
                    "title": "CORS Misconfiguration: Null Origin with Credentials",
                    "url": url,
                    "parameter": "Origin: null",
                    "evidence": "Access-Control-Allow-Origin: null with Credentials: true",
                    "description": "The application allows null origins with credentials, exploitable via sandboxed iframes.",
                    "remediation": "Reject 'null' origin headers in CORS preflight and access control responses.",
                    "cvss_score": 7.5
                })
        except Exception:
            pass

    async def _test_open_redirect(self, url: str):
        """Test for open redirection on query parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param in params.keys():
            if param.lower() in REDIRECT_PARAMS:
                test_payload = "https://example.org/sentinel_redirect_proof"
                modified_params = dict(params)
                modified_params[param] = [test_payload]
                test_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))

                try:
                    resp = await self.http_client.get(test_url, allow_redirects=False)
                    if resp and resp.status in [301, 302, 303, 307, 308]:
                        loc = resp.headers.get("Location", "")
                        if "example.org/sentinel_redirect_proof" in loc:
                            self.findings.append({
                                "type": "open_redirect",
                                "severity": "MEDIUM",
                                "title": "Open URL Redirection",
                                "url": test_url,
                                "parameter": param,
                                "evidence": f"HTTP {resp.status} -> Location: {loc}",
                                "description": f"Parameter '{param}' unsafely redirects users to arbitrary external destinations.",
                                "remediation": "Validate redirection targets against a strict server-side allowlist or use relative paths only.",
                                "cvss_score": 6.1
                            })
                except Exception:
                    pass

    async def _test_ssrf_parameters(self, url: str):
        """Identify potentially vulnerable Server-Side Request Forgery parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param in params.keys():
            if param.lower() in SSRF_PARAMS:
                self.findings.append({
                    "type": "ssrf_candidate_parameter",
                    "severity": "LOW",
                    "title": f"Potential SSRF Input Vector ('{param}')",
                    "url": url,
                    "parameter": param,
                    "evidence": f"URL contains suspected remote fetching parameter '{param}'",
                    "description": f"Parameter '{param}' may trigger backend HTTP requests and should be audited for Server-Side Request Forgery (SSRF).",
                    "remediation": "Ensure internal IP ranges (127.0.0.1, 169.254.169.254, RFC1918) are blocked from remote fetching services.",
                    "cvss_score": 4.5
                })
