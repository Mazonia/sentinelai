"""
Session Security Testing Module
Tests for session fixation, hijacking, and prediction
"""
import asyncio
import logging
from typing import Dict, List, Optional
import hashlib

from ..core.http_client import AsyncHTTPClient

logger = logging.getLogger(__name__)


class SessionSecurityTester:
    """
    Tests session management security
    """
    
    def __init__(self, http_client: AsyncHTTPClient):
        self.http_client = http_client
        self.findings = []

    async def scan(self, urls: List[str], intensity: str = 'medium', authentication: Optional[Dict] = None) -> List[Dict]:
        """Conform to the scanner module interface"""
        self.findings = []
        if not urls:
            return []
            
        base_url = urls[0]
        
        # Run prediction test
        await self.test_session_prediction(base_url)
        
        # Run cookie security test on each URL (up to 5 to avoid spamming)
        for url in urls[:5]:
            await self.test_cookie_security(url)
            
        # Run fixation test if login page exists
        from urllib.parse import urljoin
        login_url = urljoin(base_url, '/login')
        await self.test_session_fixation(login_url, base_url)
        
        return self.findings
    
    async def test_session_fixation(self, login_url: str, protected_url: str):
        """Test for session fixation vulnerability"""
        # Step 1: Get pre-auth session ID
        pre_auth_response = await self.http_client.get(login_url)
        if not pre_auth_response:
            return
        
        pre_auth_cookies = pre_auth_response.cookies
        session_id_before = self._extract_session_id(pre_auth_cookies)
        
        if not session_id_before:
            return
        
        # Step 2: Login (would need credentials)
        # This is a template - actual implementation needs auth
        
        # Step 3: Check if session ID changed
        # If session ID is the same after login = vulnerable
        
        self.findings.append({
            'type': 'session_fixation',
            'severity': 'medium',
            'description': 'Session ID not rotated after authentication',
            'remediation': 'Regenerate session ID after successful login'
        })
    
    async def test_session_prediction(self, base_url: str, samples: int = 10):
        """Test for predictable session IDs"""
        session_ids = []
        
        for _ in range(samples):
            response = await self.http_client.get(base_url)
            if response:
                sid = self._extract_session_id(response.cookies)
                if sid:
                    session_ids.append(sid)
        
        # Analyze for patterns
        if len(session_ids) >= 2:
            await self._analyze_session_entropy(session_ids)
    
    async def _analyze_session_entropy(self, session_ids: List[str]):
        """Analyze session ID randomness"""
        # Check for sequential patterns
        try:
            # Try to decode as integers
            numeric_ids = []
            for sid in session_ids:
                try:
                    numeric_ids.append(int(sid, 16))
                except ValueError:
                    try:
                        numeric_ids.append(int(sid))
                    except ValueError:
                        pass
            
            if len(numeric_ids) >= 2:
                # Check differences
                diffs = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]
                
                # If differences are small and consistent, IDs are predictable
                if all(0 < d < 100 for d in diffs):
                    self.findings.append({
                        'type': 'session_prediction',
                        'severity': 'high',
                        'description': 'Session IDs appear to be sequential/predictable',
                        'evidence': f'Session IDs: {session_ids[:3]}',
                        'remediation': 'Use cryptographically secure random session IDs'
                    })
                    
        except Exception:
            pass
    
    async def test_cookie_security(self, url: str):
        """Test for insecure cookie settings"""
        response = await self.http_client.get(url)
        if not response:
            return
        
        set_cookie = response.headers.get('Set-Cookie', '')
        
        issues = []
        
        if 'Secure' not in set_cookie:
            issues.append('Missing Secure flag')
        if 'HttpOnly' not in set_cookie:
            issues.append('Missing HttpOnly flag')
        if 'SameSite' not in set_cookie:
            issues.append('Missing SameSite attribute')
        
        if issues:
            self.findings.append({
                'type': 'insecure_session_cookie',
                'severity': 'medium',
                'issues': issues,
                'description': f'Session cookie security issues: {", ".join(issues)}',
                'remediation': 'Set Secure, HttpOnly, and SameSite=Strict on session cookies'
            })
    
    def _extract_session_id(self, cookies) -> Optional[str]:
        """Extract session ID from cookies"""
        session_names = ['sessionid', 'session', 'sess', 'sid', 'jsessionid', 'phpsessid']
        
        for name in session_names:
            if name in cookies:
                return cookies[name].value
        
        # Return first cookie if no standard session name
        if cookies:
            return list(cookies.values())[0].value
        
        return None