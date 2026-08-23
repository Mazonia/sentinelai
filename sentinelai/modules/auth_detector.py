"""
Authentication and Session Security Detection Module
"""
import asyncio
import logging
from typing import List, Dict, Any, Optional
import hashlib

from ..core.http_client import AsyncHTTPClient

logger = logging.getLogger(__name__)


class AuthDetector:
    """
    Detects authentication weaknesses and session management flaws
    """
    
    COMMON_CREDENTIALS = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('root', 'root'),
        ('root', 'password'),
        ('user', 'user'),
        ('test', 'test'),
        ('guest', 'guest'),
    ]
    
    WEAK_PASSWORDS = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'password123', 'admin', 'letmein', 'welcome', 'monkey',
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
        Scan for authentication vulnerabilities
        """
        logger.info(f"Starting auth scan on {len(urls)} URLs")
        
        # Find authentication endpoints
        auth_endpoints = self._identify_auth_endpoints(urls)
        
        tasks = []
        
        # Test each auth endpoint
        for endpoint in auth_endpoints:
            tasks.append(self._test_weak_credentials(endpoint))
            tasks.append(self._test_session_security(endpoint))
            tasks.append(self._test_brute_force_protection(endpoint))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Test for JWT issues on API endpoints
        api_urls = [u for u in urls if '/api/' in u]
        for url in api_urls:
            tasks.append(self._test_jwt_security(url))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return self.findings
    
    def _identify_auth_endpoints(self, urls: List[str]) -> List[Dict]:
        """Identify authentication endpoints from URLs"""
        auth_patterns = [
            '/login', '/signin', '/auth', '/authenticate',
            '/admin', '/dashboard', '/account',
            '/api/auth', '/api/login', '/oauth',
        ]
        
        endpoints = []
        for url in urls:
            for pattern in auth_patterns:
                if pattern in url.lower():
                    endpoints.append({
                        'url': url,
                        'type': 'login_form' if 'login' in url or 'signin' in url else 'protected_resource'
                    })
                    break
        
        return endpoints
    
    async def _test_weak_credentials(self, endpoint: Dict):
        """Test for weak/default credentials"""
        url = endpoint['url']
        
        for username, password in self.COMMON_CREDENTIALS:
            try:
                # Attempt login
                response = await self.http_client.post(
                    url,
                    data={'username': username, 'password': password}
                )
                
                if response and response.status == 200:
                    text = await response.text()
                    
                    # Check for successful login indicators
                    success_indicators = ['welcome', 'dashboard', 'logout', 'profile', 'admin']
                    failure_indicators = ['invalid', 'incorrect', 'error', 'failed']
                    
                    text_lower = text.lower()
                    has_success = any(ind in text_lower for ind in success_indicators)
                    has_failure = any(ind in text_lower for ind in failure_indicators)
                    
                    if has_success and not has_failure:
                        self.findings.append({
                            'type': 'weak_credentials',
                            'url': url,
                            'username': username,
                            'password': password,
                            'severity': 'critical',
                            'description': f"Weak/default credentials accepted: {username}/{password}",
                            'remediation': "Enforce strong password policies. Disable default accounts."
                        })
                        logger.critical(f"Weak credentials found on {url}")
                        break
                        
            except Exception as e:
                logger.debug(f"Auth test error: {e}")
    
    async def _test_session_security(self, endpoint: Dict):
        """Test session management security"""
        url = endpoint['url']
        
        try:
            response = await self.http_client.get(url)
            if not response:
                return
            
            cookies = response.cookies
            headers = response.headers
            
            # Check for secure cookie flags
            set_cookie = headers.get('Set-Cookie', '')
            
            checks = {
                'Secure': 'Secure' in set_cookie,
                'HttpOnly': 'HttpOnly' in set_cookie,
                'SameSite': 'SameSite' in set_cookie,
            }
            
            missing = [flag for flag, present in checks.items() if not present]
            
            if missing:
                self.findings.append({
                    'type': 'insecure_session',
                    'url': url,
                    'missing_flags': missing,
                    'severity': 'medium',
                    'description': f"Session cookie missing security flags: {', '.join(missing)}",
                    'remediation': "Set Secure, HttpOnly, and SameSite attributes on session cookies."
                })
            
            # Check for session fixation
            if cookies:
                for cookie in cookies.values():
                    if len(cookie.value) < 16:  # Weak session ID length
                        self.findings.append({
                            'type': 'weak_session_id',
                            'url': url,
                            'severity': 'medium',
                            'description': "Session ID appears to be weak/predictable",
                            'remediation': "Use cryptographically secure random session IDs with sufficient entropy."
                        })
            
            # Check for cache control on authenticated pages
            cache_control = headers.get('Cache-Control', '')
            if 'private' not in cache_control and 'no-store' not in cache_control:
                self.findings.append({
                    'type': 'cache_control',
                    'url': url,
                    'severity': 'low',
                    'description': "Missing cache-control headers on potentially sensitive page",
                    'remediation': "Add Cache-Control: no-store, no-cache, must-revalidate headers."
                })
                
        except Exception as e:
            logger.debug(f"Session security test error: {e}")
    
    async def _test_brute_force_protection(self, endpoint: Dict):
        """Test for brute force protection"""
        url = endpoint['url']
        
        # Make multiple rapid login attempts
        attempts = []
        for i in range(5):
            attempt = self.http_client.post(
                url,
                data={'username': f'nonexistent{i}', 'password': 'wrongpassword'}
            )
            attempts.append(attempt)
        
        responses = await asyncio.gather(*attempts, return_exceptions=True)
        
        # Check if all responses came back quickly without rate limiting
        all_200 = all(
            isinstance(r, Exception) == False and r and r.status == 200 
            for r in responses
        )
        
        if all_200:
            self.findings.append({
                'type': 'brute_force',
                'url': url,
                'severity': 'medium',
                'description': "No rate limiting detected on authentication endpoint",
                'remediation': "Implement account lockout, CAPTCHA, or rate limiting after failed attempts."
            })
    
    async def _test_jwt_security(self, url: str):
        """Test JWT implementation security"""
        # Check for JWT in URL (bad practice)
        if 'token=' in url or 'jwt=' in url:
            self.findings.append({
                'type': 'jwt_exposure',
                'url': url,
                'severity': 'medium',
                'description': "JWT token transmitted in URL parameter",
                'remediation': "Never transmit JWTs in URLs. Use Authorization header instead."
            })
        
        # Check for weak JWT signing (would require actual JWT analysis)
        # This would need a valid JWT to test
        
    async def test_password_policy(self, registration_url: str):
        """Test password policy enforcement"""
        weak_passwords = self.WEAK_PASSWORDS[:5]
        
        for password in weak_passwords:
            try:
                response = await self.http_client.post(
                    registration_url,
                    data={
                        'username': 'testuser123',
                        'password': password,
                        'confirm_password': password
                    }
                )
                
                if response and response.status == 200:
                    text = await response.text()
                    # If registration succeeded with weak password
                    if 'success' in text.lower() or 'created' in text.lower():
                        self.findings.append({
                            'type': 'weak_password_policy',
                            'url': registration_url,
                            'tested_password': password,
                            'severity': 'medium',
                            'description': "Weak password accepted during registration",
                            'remediation': "Enforce strong password requirements (length, complexity, entropy)."
                        })
                        break
                        
            except Exception as e:
                logger.debug(f"Password policy test error: {e}")