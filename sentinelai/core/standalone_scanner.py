"""
Standalone Scanning Engine
Orchestrates Recon, Crawling, Complete Vulnerability Suite, and AI Analysis without DB dependencies.
"""
import asyncio
import logging
from typing import List, Dict, Any, Optional, Callable
from urllib.parse import urlparse

from .http_client import AsyncHTTPClient
from .crawler import WebCrawler
from ..modules.injection_detector import InjectionDetector
from ..modules.xss_detector import XSSDetector
from ..modules.config_detector import ConfigDetector
from ..modules.auth_detector import AuthDetector
from ..modules.api_detector import APIDetector
from ..modules.dir_fuzzer import DirFuzzer
from ..modules.cors_ssrf_detector import CORSSSRFDetector
from ..modules.traversal_detector import PathTraversalDetector
from ..modules.session_hijacking import SessionSecurityTester
from ..modules.recon_detector import ReconDetector
from ..ai.cli_analyzer import CLIAnalyzer

logger = logging.getLogger(__name__)


class StandaloneScanner:
    """
    Zero-database portable security scanner covering full OWASP Top 10
    """

    def __init__(self, concurrency: int = 15, timeout: int = 20):
        self.http_client = AsyncHTTPClient(timeout=timeout, max_concurrent=concurrency)
        self.crawler = WebCrawler(self.http_client)
        self.recon = ReconDetector()
        self.analyzer = CLIAnalyzer()

        # Complete Security Audit Suite
        self.detectors = {
            "config": ConfigDetector(self.http_client),
            "cors_ssrf": CORSSSRFDetector(self.http_client),
            "traversal": PathTraversalDetector(self.http_client),
            "injection": InjectionDetector(self.http_client),
            "xss": XSSDetector(self.http_client),
            "auth": AuthDetector(self.http_client),
            "api": APIDetector(self.http_client),
            "session": SessionSecurityTester(self.http_client),
            "fuzzer": DirFuzzer(self.http_client, concurrency=concurrency),
        }

    async def run_full_scan(
        self,
        target_url: str,
        enable_ai: bool = True,
        progress_cb: Optional[Callable[[str, int], None]] = None
    ) -> Dict[str, Any]:
        """Execute full scan lifecycle: Recon -> Crawl -> Audit -> AI Enrich"""
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        results = {
            "target": target_url,
            "recon": {},
            "crawled_urls": [],
            "findings": []
        }

        # Step 1: Reconnaissance & OSINT
        if progress_cb:
            progress_cb("Performing Reconnaissance & OSINT Fingerprinting...", 10)
        recon_data = await self.recon.scan_domain(target_url)
        results["recon"] = recon_data

        # Step 2: Web Crawling
        if progress_cb:
            progress_cb("Crawling web endpoints & discovering attack surface...", 25)
        try:
            crawled_urls = await self.crawler.crawl(target_url, max_depth=2, max_pages=25)
        except Exception:
            crawled_urls = [target_url]
        results["crawled_urls"] = list(crawled_urls) if crawled_urls else [target_url]

        # Step 3: Vulnerability Auditing across full suite
        raw_findings = []
        scan_list = results["crawled_urls"][:15]

        step_pct = 35
        pct_step = max(1, 55 // len(self.detectors))

        discovered_forms = getattr(self.crawler, 'forms', [])
        results["forms_discovered"] = len(discovered_forms)

        for name, detector in self.detectors.items():
            if progress_cb:
                progress_cb(f"Auditing target for {name.upper()} vulnerabilities...", step_pct)
            step_pct = min(90, step_pct + pct_step)
            try:
                if name in ["injection", "xss"]:
                    mod_findings = await detector.scan(scan_list, intensity="medium", forms=discovered_forms)
                else:
                    mod_findings = await detector.scan(scan_list, intensity="medium")
                for f in mod_findings:
                    f["module"] = name
                    raw_findings.append(f)
            except Exception as e:
                logger.debug(f"Detector {name} failed: {e}")

        # Step 4: AI Analysis & False-Positive Elimination
        if progress_cb:
            progress_cb("Running AI Vulnerability Correlation & Remediation...", 92)
        enriched_findings = await self.analyzer.analyze_findings(raw_findings)
        results["findings"] = enriched_findings

        if progress_cb:
            progress_cb("Scan Complete!", 100)

        await self.http_client.close()
        return results
