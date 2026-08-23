"""
Security Configuration and Information Disclosure Detection Module
"""
import asyncio
import logging
from typing import List, Dict, Any, Optional
import ssl
import json
from urllib.parse import urlparse

from ..core.http_client import AsyncHTTPClient

logger = logging.getLogger(__name__)


class ConfigDetector:
    """
    Detects security misconfigurations and information disclosure
    """
    
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'HSTS not configured',
        'Content-Security-Policy': 'CSP not configured',
        'X-Frame-Options': 'Clickjacking protection missing',
        'X-Content-Type-Options': 'MIME sniffing protection missing',
        'Referrer-Policy': 'Referrer policy not set',
        'Permissions-Policy': 'Permissions policy not set',
    }
    
    SENSITIVE_FILES = [
        '/.env', '/.env.local', '/.env.production',
        '/config.json', '/config.js', '/configuration.json',
        '/.git/config', '/.git/HEAD', '/.git/index',
        '/.svn/entries', '/.hg/hgrc',
        '/backup/', '/backups/', '/backup.zip', '/backup.tar.gz',
        '/dump.sql', '/database.sql', '/db.sql',
        '/.htaccess', '/.htpasswd',
        '/server-status', '/server-info',
        '/phpinfo.php', '/info.php', '/test.php',
        '/api/swagger.json', '/api/docs', '/swagger-ui.html',
        '/.well-known/security.txt',
        '/robots.txt', '/sitemap.xml',
        '/Dockerfile', '/docker-compose.yml',
        '/package.json', '/requirements.txt', '/Gemfile',
        '/.aws/credentials', '/.ssh/id_rsa',
    ]
    
    def __init__(self, http_client: AsyncHTTPClient):
        self.http_client = http_client
        self.findings = []
    
    async def scan(
        self,
        urls: List[str],
        intensity: str = "medium",
        authentication: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Scan for security misconfigurations
        """
        logger.info(f"Starting config scan on {len(urls)} URLs")
        
        if not urls:
            return self.findings
        
        base_url = urls[0]
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check security headers
        await self._check_security_headers(base)
        
        # Check for sensitive files
        await self._check_sensitive_files(base)
        
        # Check SSL/TLS configuration
        await self._check_ssl_configuration(parsed.netloc)
        
        # Check CORS configuration
        await self._check_cors_configuration(base)
        
        return self.findings
    
    async def _check_security_headers(self, base_url: str):
        """Check for missing security headers"""
        try:
            response = await self.http_client.get(base_url)
            if not response:
                return
            
            headers = response.headers
            
            missing_headers = []
            for header, description in self.SECURITY_HEADERS.items():
                if header not in headers:
                    missing_headers.append({
                        'header': header,
                        'description': description
                    })
            
            if missing_headers:
                self.findings.append({
                    'type': 'missing_security_headers',
                    'url': base_url,
                    'missing': missing_headers,
                    'severity': 'medium',
                    'description': f"Missing {len(missing_headers)} security headers",
                    'remediation': "Implement comprehensive security headers including CSP, HSTS, and X-Frame-Options."
                })
            
            # Check for server version disclosure
            server = headers.get('Server', '')
            x_powered_by = headers.get('X-Powered-By', '')
            
            if server or x_powered_by:
                self.findings.append({
                    'type': 'information_disclosure',
                    'url': base_url,
                    'server_header': server,
                    'x_powered_by': x_powered_by,
                    'severity': 'low',
                    'description': "Server version information exposed in headers",
                    'remediation': "Remove or obfuscate Server and X-Powered-By headers."
                })
            
            # Check for insecure cookie settings
            set_cookie = headers.get('Set-Cookie', '')
            if set_cookie:
                cookie_issues = []
                if 'Secure' not in set_cookie:
                    cookie_issues.append("Missing Secure flag")
                if 'HttpOnly' not in set_cookie:
                    cookie_issues.append("Missing HttpOnly flag")
                if 'SameSite' not in set_cookie:
                    cookie_issues.append("Missing SameSite attribute")
                
                if cookie_issues:
                    self.findings.append({
                        'type': 'insecure_cookies',
                        'url': base_url,
                        'issues': cookie_issues,
                        'severity': 'medium',
                        'description': f"Cookie security issues: {', '.join(cookie_issues)}",
                        'remediation': "Set Secure, HttpOnly, and SameSite attributes on all cookies."
                    })
                    
        except Exception as e:
            logger.debug(f"Security headers check error: {e}")
    
    async def _check_sensitive_files(self, base_url: str):
        """Check for exposed sensitive files"""
        tasks = []
        for file_path in self.SENSITIVE_FILES:
            url = f"{base_url}{file_path}"
            tasks.append(self._check_single_file(url, file_path))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _check_single_file(self, url: str, file_path: str):
        """Check if a specific sensitive file is accessible"""
        try:
            response = await self.http_client.get(url)
            
            if response and response.status == 200:
                content_length = int(response.headers.get('Content-Length', 0))
                
                # Skip if too small (likely 404 page)
                if content_length > 0 and content_length < 100:
                    return
                
                text = await response.text()
                
                # Check if it's actually the sensitive file
                indicators = {
                    '.env': ['=', 'DB_', 'API_', 'SECRET', 'PASSWORD'],
                    '.git/config': ['[core]', 'repositoryformatversion'],
                    'config.json': ['"port"', '"database"', '"password"'],
                    'phpinfo': ['phpinfo()', 'PHP Version'],
                    'swagger': ['swagger', 'openapi', '"paths"'],
                    'package.json': ['"dependencies"', '"name"'],
                }
                
                is_valid = False
                for key, patterns in indicators.items():
                    if key in file_path.lower():
                        if any(p in text for p in patterns):
                            is_valid = True
                            break
                
                if is_valid or content_length > 500:
                    severity = 'high' if any(x in file_path for x in ['.env', '.git', 'credentials', 'id_rsa']) else 'medium'
                    
                    self.findings.append({
                        'type': 'sensitive_file_exposure',
                        'url': url,
                        'file': file_path,
                        'size': content_length,
                        'severity': severity,
                        'description': f"Sensitive file exposed: {file_path}",
                        'remediation': "Remove sensitive files from web root. Use proper access controls."
                    })
                    logger.warning(f"Sensitive file found: {url}")
                    
        except Exception as e:
            logger.debug(f"File check error for {url}: {e}")
    
    async def _check_ssl_configuration(self, hostname: str):
        """Check SSL/TLS configuration"""
        try:
            import socket
            import ssl as ssl_module
            
            context = ssl_module.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    issues = []
                    
                    # Check TLS version
                    if version in ['TLSv1', 'TLSv1.1']:
                        issues.append(f"Outdated TLS version: {version}")
                    
                    # Check certificate expiration
                    from datetime import datetime
                    not_after = cert.get('notAfter')
                    if not_after:
                        # Parse and check expiration
                        pass
                    
                    # Check weak ciphers
                    if cipher and 'RC4' in str(cipher):
                        issues.append("Weak cipher: RC4")
                    if cipher and 'DES' in str(cipher):
                        issues.append("Weak cipher: DES")
                    
                    if issues:
                        self.findings.append({
                            'type': 'ssl_misconfiguration',
                            'hostname': hostname,
                            'tls_version': version,
                            'issues': issues,
                            'severity': 'high',
                            'description': f"SSL/TLS issues: {', '.join(issues)}",
                            'remediation': "Disable SSLv2/SSLv3/TLS1.0/TLS1.1. Use only strong cipher suites."
                        })
                        
        except Exception as e:
            logger.debug(f"SSL check error: {e}")
    
    async def _check_cors_configuration(self, base_url: str):
        """Check CORS (Cross-Origin Resource Sharing) configuration"""
        test_origins = [
            'https://evil.com',
            'null',
            'https://attacker.github.io',
        ]
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                response = await self.http_client.get(base_url, headers=headers)
                
                if not response:
                    continue
                
                acao = response.headers.get('Access-Control-Allow-Origin')
                acac = response.headers.get('Access-Control-Allow-Credentials')
                
                if acao == '*':
                    self.findings.append({
                        'type': 'cors_misconfiguration',
                        'url': base_url,
                        'issue': 'Wildcard origin allowed',
                        'severity': 'medium',
                        'description': "CORS allows any origin (*)",
                        'remediation': "Specify exact allowed origins instead of wildcard."
                    })
                    break
                
                if acao == origin:
                    if acac == 'true':
                        self.findings.append({
                            'type': 'cors_misconfiguration',
                            'url': base_url,
                            'issue': 'Arbitrary origin reflected with credentials',
                            'severity': 'high',
                            'description': "CORS reflects arbitrary Origin header and allows credentials",
                            'remediation': "Validate Origin header against whitelist. Don't reflect arbitrary origins with credentials."
                        })
                        break
                        
            except Exception as e:
                logger.debug(f"CORS check error: {e}")
    
    async def check_method_interaction(self, url: str):
        """Check for dangerous HTTP method support"""
        methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']
        
        for method in methods:
            try:
                response = await self.http_client.request(method, url)
                
                if response and response.status not in [405, 403, 401]:
                    self.findings.append({
                        'type': 'dangerous_http_method',
                        'url': url,
                        'method': method,
                        'status': response.status,
                        'severity': 'low',
                        'description': f"Potentially dangerous HTTP method enabled: {method}",
                        'remediation': f"Disable {method} method if not required."
                    })
                    
            except Exception:
                pass