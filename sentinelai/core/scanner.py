"""
SentinelAI Security Scanner - Core scanning orchestration
"""
import asyncio
import logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse
import json

from .http_client import AsyncHTTPClient
from .crawler import WebCrawler
from ..models.database import ScanResult, Vulnerability, Target, ScanStatus as DBScanStatus
from ..modules.injection_detector import InjectionDetector
from ..modules.xss_detector import XSSDetector
from ..modules.auth_detector import AuthDetector
from ..modules.config_detector import ConfigDetector
from ..modules.api_detector import APIDetector
from ..ai.analyzer import AIAnalyzer
from ..modules.privilege_escalation import PrivilegeEscalationTester
from ..modules.session_hijacking import SessionSecurityTester
from ..modules.automated_exploitation import AutomatedExploitation


logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Configuration for a security scan"""
    target_url: str
    max_depth: int = 3
    max_pages: int = 100
    concurrency: int = 10
    timeout: int = 30
    follow_redirects: bool = True
    respect_robots_txt: bool = False
    authentication: Optional[Dict] = None
    custom_headers: Dict = field(default_factory=dict)
    excluded_paths: List[str] = field(default_factory=list)
    included_modules: List[str] = field(default_factory=lambda: [
        'injection', 'xss', 'auth', 'config', 'api'
    ])
    ai_analysis: bool = True
    payload_intensity: str = "medium"  # low, medium, high


@dataclass
class ScanStatus:
    """Current status of a scan"""
    scan_id: str
    target: str
    status: str  # pending, running, completed, failed
    pages_discovered: int = 0
    pages_scanned: int = 0
    vulnerabilities_found: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    current_module: str = ""
    error_message: Optional[str] = None


class SecurityScanner:
    """
    Main security scanner orchestrating all detection modules
    """
    
    def __init__(self, config: ScanConfig, db_session=None):
        self.config = config
        self.db_session = db_session
        self.http_client = AsyncHTTPClient(
            timeout=config.timeout,
            max_concurrent=config.concurrency,
            custom_headers=config.custom_headers
        )
        self.crawler = WebCrawler(self.http_client)
        self.ai_analyzer = AIAnalyzer() if config.ai_analysis else None
        
        # Import escalation modules
        from ..modules.privilege_escalation import PrivilegeEscalationTester
        from ..modules.session_hijacking import SessionSecurityTester
        from ..modules.automated_exploitation import AutomatedExploitation
        
        # Initialize detection modules
        self.modules = {}
        if 'injection' in config.included_modules:
            self.modules['injection'] = InjectionDetector(self.http_client)
        if 'xss' in config.included_modules:
            self.modules['xss'] = XSSDetector(self.http_client)
        if 'auth' in config.included_modules:
            self.modules['auth'] = AuthDetector(self.http_client)
        if 'config' in config.included_modules:
            self.modules['config'] = ConfigDetector(self.http_client)
        if 'api' in config.included_modules:
            self.modules['api'] = APIDetector(self.http_client)
        if 'privilege' in config.included_modules:
            self.modules['privilege'] = PrivilegeEscalationTester(self.http_client)
        if 'session' in config.included_modules:
            self.modules['session'] = SessionSecurityTester(self.http_client)
        
        # NEW: Automated exploitation (runs after detection)
        self.exploitation = AutomatedExploitation(self.http_client)
        
        self.status = ScanStatus(
            scan_id=self._generate_scan_id(),
            target=config.target_url,
            status="pending"
        )
        self.vulnerabilities: List[Vulnerability] = []
        self.discovered_urls: set = set()
        self.progress_callbacks: List[Callable] = []
        
        logger.info(f"Initialized scanner for {config.target_url}")
        self.status = ScanStatus(
            scan_id=self._generate_scan_id(),
            target=config.target_url,
            status="pending"
        )
        self.vulnerabilities: List[Vulnerability] = []
        self.discovered_urls: set = set()
        self.progress_callbacks: List[Callable] = []
        
        logger.info(f"Initialized scanner for {config.target_url}")
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def register_progress_callback(self, callback: Callable):
        """Register callback for progress updates"""
        self.progress_callbacks.append(callback)
    
    def _notify_progress(self):
        """Notify all registered callbacks"""
        for callback in self.progress_callbacks:
            try:
                callback(self.status)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")
    
    async def start_scan(self) -> ScanStatus:
        """Execute the complete security scan"""
        self.status.status = "running"
        self.status.start_time = datetime.utcnow()
        logger.info(f"Starting scan {self.status.scan_id} for {self.config.target_url}")
        
        try:
            # Phase 1: Discovery
            await self._discovery_phase()
            
            # Phase 2: Vulnerability Scanning
            await self._scanning_phase()
            
            # Phase 3: Safe Exploitation
            await self._exploitation_phase()
            
            # Phase 4: AI Analysis (if enabled)
            if self.ai_analyzer and self.vulnerabilities:
                await self._ai_analysis_phase()
            
            self.status.status = "completed"
            self.status.end_time = datetime.utcnow()
            
            # Save results to database
            await self._save_results()
            
        except Exception as e:
            logger.exception("Scan failed")
            self.status.status = "failed"
            self.status.error_message = str(e)
        
        self._notify_progress()
        return self.status
    
    async def _discovery_phase(self):
        """Crawl and discover all endpoints"""
        logger.info("Starting discovery phase")
        self.status.current_module = "discovery"
        self._notify_progress()
        
        discovered = await self.crawler.crawl(
            self.config.target_url,
            max_depth=self.config.max_depth,
            max_pages=self.config.max_pages,
            exclude_paths=self.config.excluded_paths
        )
        
        self.discovered_urls = discovered
        self.status.pages_discovered = len(discovered)
        self._notify_progress()
        
        logger.info(f"Discovered {len(discovered)} URLs")
    
    async def _scanning_phase(self):
        """Run all enabled vulnerability detection modules"""
        urls = list(self.discovered_urls)
        
        for module_name, module in self.modules.items():
            if self.status.status == "cancelled":
                logger.info("Scan cancelled, aborting scanning phase")
                break

            logger.info(f"Running {module_name} detection module")
            self.status.current_module = module_name
            self._notify_progress()
            
            try:
                findings = await module.scan(
                    urls,
                    intensity=self.config.payload_intensity,
                    authentication=self.config.authentication
                )
                
                from sqlalchemy import inspect
                from ..models.database import Severity
                valid_columns = {c.key for c in inspect(Vulnerability).mapper.column_attrs}
                
                for finding in findings:
                    vuln_args = {}
                    evidence_dict = {}
                    for k, v in finding.items():
                        if k in valid_columns:
                            vuln_args[k] = v
                        else:
                            evidence_dict[k] = v
                            
                    if evidence_dict:
                        vuln_args['evidence'] = evidence_dict
                        
                    if not vuln_args.get('url'):
                        vuln_args['url'] = self.config.target_url
                        
                    if 'severity' in vuln_args and isinstance(vuln_args['severity'], str):
                        try:
                            vuln_args['severity'] = Severity[vuln_args['severity'].upper()]
                        except Exception:
                            vuln_args['severity'] = Severity.INFO
                            
                    vuln = Vulnerability(
                        scan_id=self.status.scan_id,
                        module=module_name,
                        **vuln_args
                    )
                    self.vulnerabilities.append(vuln)
                
                self.status.vulnerabilities_found = len(self.vulnerabilities)
                self.status.pages_scanned += len(urls)
                self._notify_progress()
                
            except Exception as e:
                logger.error(f"Module {module_name} failed: {e}")

    async def _exploitation_phase(self):
        """Attempt safe exploitation of confirmed vulnerabilities"""
        logger.info("Starting exploitation phase")
        self.status.current_module = "exploitation"
        self._notify_progress()
        
        # Only exploit high-confidence findings
        for vuln in self.vulnerabilities:
            if self.status.status == "cancelled":
                logger.info("Scan cancelled, aborting exploitation phase")
                break
            confidence_score = vuln.confidence if vuln.confidence is not None else 0.5
            if vuln.false_positive or confidence_score < 0.7:
                continue
            
            try:
                if vuln.type == 'sql_injection':
                    result = await self.exploitation.safe_exploit_sql_injection(
                        vuln.url,
                        vuln.parameter,
                        'mysql'  # or detect from evidence
                    )
                    if result.get('success'):
                        vuln.exploitation_confirmed = True
                        vuln.exploitation_proof = result.get('proof')
                
                elif vuln.type == 'xss':
                    result = await self.exploitation.safe_exploit_xss(
                        vuln.url,
                        vuln.parameter
                    )
                    if result.get('success'):
                        vuln.exploitation_confirmed = True
                
                elif vuln.type == 'privilege_escalation':
                    # Would need session info here
                    pass
                    
            except Exception as e:
                logger.error(f"Exploitation error: {e}")
                
    async def _ai_analysis_phase(self):
        """Use AI to analyze and prioritize findings"""
        logger.info("Starting AI analysis phase")
        self.status.current_module = "ai_analysis"
        self._notify_progress()
        
        analyzed_vulns = await self.ai_analyzer.analyze_vulnerabilities(
            self.vulnerabilities,
            self.config.target_url
        )
        
        self.vulnerabilities = analyzed_vulns
    
    async def _save_results(self):
        """Save scan results to database"""
        if not self.db_session:
            return
        
        try:
            result = ScanResult(
                scan_id=self.status.scan_id,
                target=self.config.target_url,
                status=DBScanStatus[self.status.status.upper()] if self.status.status else DBScanStatus.PENDING,
                start_time=self.status.start_time,
                end_time=self.status.end_time,
                pages_discovered=self.status.pages_discovered,
                pages_scanned=self.status.pages_scanned,
                vulnerability_count=len(self.vulnerabilities),
                vulnerabilities=self.vulnerabilities,
                config={
                    "max_depth": self.config.max_depth,
                    "max_pages": self.config.max_pages,
                    "concurrency": self.config.concurrency,
                    "included_modules": self.config.included_modules,
                    "ai_analysis": self.config.ai_analysis,
                    "payload_intensity": self.config.payload_intensity
                }
            )
            self.db_session.add(result)
            await self.db_session.flush()
            
            # Populate findings JSON with the flushed/saved models (which now have DB IDs)
            result.findings = [v.to_dict() for v in self.vulnerabilities]
            await self.db_session.commit()
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
    
    def get_report(self) -> Dict:
        """Generate comprehensive scan report"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in self.vulnerabilities:
            sev_str = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            severity_counts[sev_str.lower()] = severity_counts.get(sev_str.lower(), 0) + 1
        
        return {
            "scan_id": self.status.scan_id,
            "target": self.config.target_url,
            "status": self.status.status,
            "duration": (self.status.end_time - self.status.start_time).total_seconds() if self.status.end_time else None,
            "summary": {
                "pages_discovered": self.status.pages_discovered,
                "pages_scanned": self.status.pages_scanned,
                "vulnerabilities_found": len(self.vulnerabilities),
                "severity_distribution": severity_counts
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "modules_used": list(self.modules.keys()),
            "ai_analysis_enabled": self.ai_analyzer is not None
        }
    
    async def close(self):
        """Cleanup resources"""
        await self.http_client.close()