"""
Privilege Escalation Testing Module
FOR AUTHORIZED SECURITY TESTING ONLY - Only use on systems you own
"""
import asyncio
import logging
from typing import List, Dict, Optional
from urllib.parse import urljoin

from ..core.http_client import AsyncHTTPClient

logger = logging.getLogger(__name__)


class PrivilegeEscalationTester:
    """
    Tests for privilege escalation vulnerabilities in web applications
    FOR AUTHORIZED TESTING ONLY
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
        user_creds = (authentication or {}).get('credentials', {'username': 'testuser', 'password': 'testuser'})
        admin_indicators = ['admin', 'administrator', 'dashboard', 'controlpanel', 'settings']
        
        await self.test_escalation_paths(base_url, user_creds, admin_indicators)
        return self.findings
    
    async def test_escalation_paths(
        self,
        base_url: str,
        user_credentials: Dict[str, str],  # Low-priv user creds
        admin_indicators: List[str]
    ) -> List[Dict]:
        """
        Test privilege escalation from normal user to admin
        """
        # Login as low-priv user
        session = await self._authenticate(base_url, user_credentials)
        if not session:
            logger.error("Failed to authenticate as test user")
            return []
        
        # Find admin endpoints
        admin_endpoints = await self._discover_admin_endpoints(base_url, admin_indicators)
        
        # Test access to admin functions
        for endpoint in admin_endpoints:
            # Test 1: Direct access attempt
            await self._test_direct_access(session, endpoint)
            
            # Test 2: Parameter tampering
            await self._test_parameter_tampering(session, endpoint)
            
            # Test 3: HTTP method switching
            await self._test_method_switching(session, endpoint)
            
            # Test 4: Header manipulation
            await self._test_header_manipulation(session, endpoint)
        
        # Test 5: JWT/token manipulation if applicable
        await self._test_token_manipulation(session)
        
        # Test 6: IDOR to admin resources
        await self._test_idor_to_admin(session, base_url)
        
        return self.findings
    
    async def _authenticate(self, base_url: str, credentials: Dict) -> Optional[Dict]:
        """Authenticate and return session"""
        login_url = urljoin(base_url, '/login')
        
        try:
            response = await self.http_client.post(
                login_url,
                data=credentials
            )
            
            if response and response.status == 200:
                # Extract session info
                cookies = response.cookies
                headers = dict(response.headers)
                
                return {
                    'cookies': cookies,
                    'headers': headers,
                    'authenticated': True
                }
        except Exception as e:
            logger.error(f"Auth error: {e}")
        
        return None
    
    async def _discover_admin_endpoints(
        self,
        base_url: str,
        indicators: List[str]
    ) -> List[str]:
        """Discover potential admin endpoints"""
        common_admin_paths = [
            '/admin', '/administrator', '/admin/dashboard',
            '/api/admin', '/api/v1/admin', '/api/v2/admin',
            '/manage', '/management', '/panel',
            '/superuser', '/root', '/backend',
            '/admin/users', '/admin/settings',
            '/admin/roles', '/admin/permissions',
        ]
        
        discovered = []
        
        for path in common_admin_paths:
            url = urljoin(base_url, path)
            try:
                response = await self.http_client.get(url)
                if response and response.status in [200, 403, 401]:
                    # Check if it matches admin indicators
                    text = await response.text()
                    if any(ind.lower() in text.lower() for ind in indicators):
                        discovered.append(url)
            except Exception:
                pass
        
        return discovered
    
    async def _test_direct_access(self, session: Dict, endpoint: str):
        """Test if low-priv user can access admin endpoint directly"""
        try:
            response = await self.http_client.get(
                endpoint,
                cookies=session.get('cookies'),
                headers=session.get('headers', {})
            )
            
            if response and response.status == 200:
                text = await response.text()
                
                # Check if we actually got admin access
                admin_markers = ['admin panel', 'dashboard', 'manage users', 'settings']
                if any(marker in text.lower() for marker in admin_markers):
                    self.findings.append({
                        'type': 'privilege_escalation',
                        'subtype': 'broken_access_control',
                        'severity': 'critical',
                        'url': endpoint,
                        'description': 'Low-privilege user can access admin endpoint directly',
                        'evidence': f'Status 200 with admin content accessible',
                        'remediation': 'Implement proper role-based access control (RBAC) on all admin endpoints'
                    })
                    
        except Exception as e:
            logger.debug(f"Direct access test error: {e}")
    
    async def _test_parameter_tampering(self, session: Dict, endpoint: str):
        """Test parameter-based privilege escalation"""
        # Common privilege escalation parameters
        tampered_params = [
            {'role': 'admin'},
            {'role': 'administrator'},
            {'is_admin': 'true'},
            {'admin': '1'},
            {'privilege': 'superuser'},
            {'user_type': 'admin'},
        ]
        
        for params in tampered_params:
            try:
                response = await self.http_client.get(
                    endpoint,
                    params=params,
                    cookies=session.get('cookies')
                )
                
                if response and response.status == 200:
                    self.findings.append({
                        'type': 'privilege_escalation',
                        'subtype': 'parameter_tampering',
                        'severity': 'critical',
                        'url': endpoint,
                        'parameter': list(params.keys())[0],
                        'value': list(params.values())[0],
                        'description': f'Privilege escalation via parameter tampering: {params}',
                        'remediation': 'Never trust client-side parameters for privilege checks. Validate server-side.'
                    })
                    break
                    
            except Exception:
                pass
    
    async def _test_method_switching(self, session: Dict, endpoint: str):
        """Test HTTP method switching for bypass"""
        methods = ['POST', 'PUT', 'PATCH', 'DELETE']
        
        for method in methods:
            try:
                response = await self.http_client.request(
                    method,
                    endpoint,
                    cookies=session.get('cookies')
                )
                
                if response and response.status == 200:
                    self.findings.append({
                        'type': 'privilege_escalation',
                        'subtype': 'http_method_bypass',
                        'severity': 'high',
                        'url': endpoint,
                        'method': method,
                        'description': f'Access control bypass via HTTP {method} method',
                        'remediation': 'Apply authorization checks consistently across all HTTP methods'
                    })
                    
            except Exception:
                pass
    
    async def _test_header_manipulation(self, session: Dict, endpoint: str):
        """Test header-based privilege escalation"""
        headers_to_test = [
            {'X-Role': 'admin'},
            {'X-User-Role': 'administrator'},
            {'X-Is-Admin': 'true'},
            {'X-Original-User': 'admin'},
            {'X-Forwarded-User': 'admin'},
            {'X-Remote-User': 'admin'},
        ]
        
        for headers in headers_to_test:
            try:
                response = await self.http_client.get(
                    endpoint,
                    headers=headers,
                    cookies=session.get('cookies')
                )
                
                if response and response.status == 200:
                    self.findings.append({
                        'type': 'privilege_escalation',
                        'subtype': 'header_manipulation',
                        'severity': 'critical',
                        'url': endpoint,
                        'header': headers,
                        'description': f'Privilege escalation via header manipulation',
                        'remediation': 'Do not trust client-provided headers for authorization decisions'
                    })
                    
            except Exception:
                pass
    
    async def _test_token_manipulation(self, session: Dict):
        """Test JWT/token manipulation for escalation"""
        # This would check for weak JWT signing, algorithm confusion, etc.
        # Implementation depends on token format
        
        # Check for JWT in session
        auth_header = session.get('headers', {}).get('Authorization', '')
        if 'Bearer ' in auth_header:
            token = auth_header.split('Bearer ')[1]
            
            # Test for algorithm confusion (alg: none)
            await self._test_jwt_none_algorithm(token, session)
            
            # Test for weak signing
            await self._test_jwt_weak_secret(token, session)
    
    async def _test_jwt_none_algorithm(self, token: str, session: Dict):
        """Test JWT 'none' algorithm vulnerability"""
        import base64
        import json
        
        try:
            # Decode header
            parts = token.split('.')
            if len(parts) != 3:
                return
            
            header = json.loads(base64.b64decode(parts[0] + '=='))
            payload = json.loads(base64.b64decode(parts[1] + '=='))
            
            # Modify algorithm to none
            header['alg'] = 'none'
            new_token = f"{base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')}.{base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')}."
            
            # Test with modified token
            # This would require knowing an endpoint to test against
            
        except Exception:
            pass
    
    async def _test_jwt_weak_secret(self, token: str, session: Dict):
        """Test for weak JWT signing secrets"""
        # Would test against common weak secrets
        common_secrets = [
            'secret', 'password', '123456', 'admin', 'key',
            'jwt', 'token', 'supersecret', 'your-256-bit-secret'
        ]
        
        # Implementation would verify token with each secret
        pass
    
    async def _test_idor_to_admin(self, session: Dict, base_url: str):
        """Test for IDOR leading to admin data access"""
        # Look for user ID patterns that might lead to admin data
        id_patterns = [0, 1, -1, 999, 9999]
        
        for user_id in id_patterns:
            test_url = f"{base_url}/api/users/{user_id}"
            try:
                response = await self.http_client.get(
                    test_url,
                    cookies=session.get('cookies')
                )
                
                if response and response.status == 200:
                    text = await response.text()
                    if 'admin' in text.lower() or 'role' in text.lower():
                        self.findings.append({
                            'type': 'privilege_escalation',
                            'subtype': 'idor',
                            'severity': 'high',
                            'url': test_url,
                            'description': f'Potential admin data access via IDOR (ID: {user_id})',
                            'remediation': 'Implement authorization checks for every resource access'
                        })
                        
            except Exception:
                pass