"""
API Security Detection Module
"""
import asyncio
import logging
from typing import List, Dict, Any, Optional
import json

from ..core.http_client import AsyncHTTPClient

logger = logging.getLogger(__name__)


class APIDetector:
    """
    Detects API-specific vulnerabilities including IDOR, mass assignment,
    and authentication bypasses
    """
    
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
        Scan API endpoints for vulnerabilities
        """
        logger.info(f"Starting API scan on {len(urls)} URLs")
        
        # Filter for API endpoints
        api_urls = [u for u in urls if any(x in u for x in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/'])]
        
        if not api_urls:
            return self.findings
        
        tasks = []
        
        for url in api_urls:
            tasks.append(self._test_idor(url))
            tasks.append(self._test_mass_assignment(url))
            tasks.append(self._test_http_method_switching(url))
            tasks.append(self._test_graphql_introspection(url))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return self.findings
    
    async def _test_idor(self, url: str):
        """
        Test for Insecure Direct Object Reference (IDOR)
        """
        # Look for numeric IDs in URL
        import re
        
        id_patterns = [
            (r'/\d+', '/{other_id}'),  # /users/123 -> /users/124
            (r'\?id=\d+', '?id={other_id}'),
            (r'\?user_id=\d+', '?user_id={other_id}'),
            (r'\?order_id=\d+', '?order_id={other_id}'),
        ]
        
        for pattern, replacement_template in id_patterns:
            match = re.search(pattern, url)
            if match:
                original_id = int(re.search(r'\d+', match.group()).group())
                
                # Try adjacent IDs
                for offset in [1, -1, 2, -2]:
                    test_id = original_id + offset
                    if test_id < 1:
                        continue
                    
                    test_url = re.sub(pattern, replacement_template.format(other_id=test_id), url)
                    
                    try:
                        response = await self.http_client.get(test_url)
                        
                        if response and response.status == 200:
                            text = await response.text()
                            
                            # Check if we got different data
                            if len(text) > 100:  # Has content
                                self.findings.append({
                                    'type': 'idor',
                                    'url': url,
                                    'tested_url': test_url,
                                    'original_id': original_id,
                                    'test_id': test_id,
                                    'severity': 'high',
                                    'description': f"Potential IDOR: Accessed resource {test_id} by modifying ID parameter",
                                    'remediation': "Implement proper authorization checks. Use indirect reference maps."
                                })
                                logger.warning(f"IDOR found: {url}")
                                break
                                
                    except Exception as e:
                        logger.debug(f"IDOR test error: {e}")
    
    async def _test_mass_assignment(self, url: str):
        """
        Test for mass assignment vulnerabilities
        """
        # Common sensitive fields that shouldn't be user-writable
        sensitive_fields = [
            'is_admin', 'admin', 'role', 'permissions',
            'id', 'user_id', 'account_id',
            'created_at', 'updated_at',
            'password', 'password_hash',
            'api_key', 'secret', 'token',
        ]
        
        # Test by adding extra fields to POST/PUT requests
        test_data = {field: 'test_value' for field in sensitive_fields[:3]}
        
        try:
            # Try POST
            response = await self.http_client.post(url, json=test_data)
            
            if response and response.status in [200, 201]:
                # Check if fields were accepted
                text = await response.text()
                
                for field in sensitive_fields[:3]:
                    if field in text.lower():
                        self.findings.append({
                            'type': 'mass_assignment',
                            'url': url,
                            'field': field,
                            'severity': 'high',
                            'description': f"Mass assignment vulnerability: '{field}' parameter accepted",
                            'remediation': "Use allowlists for permitted parameters. Never bind user input directly to model attributes."
                        })
                        break
                        
        except Exception as e:
            logger.debug(f"Mass assignment test error: {e}")
    
    async def _test_http_method_switching(self, url: str):
        """
        Test for authentication bypass via HTTP method switching
        """
        # If URL has authentication, try method switching
        
        methods_to_test = ['POST', 'PUT', 'PATCH']
        
        for method in methods_to_test:
            try:
                response = await self.http_client.request(method, url)
                
                # If we get success without auth, it might be a bypass
                if response and response.status in [200, 201, 204]:
                    self.findings.append({
                        'type': 'method_switching',
                        'url': url,
                        'method': method,
                        'severity': 'medium',
                        'description': f"HTTP {method} succeeded where authentication might be expected",
                        'remediation': "Apply authentication consistently across all HTTP methods."
                    })
                    
            except Exception:
                pass
    
    async def _test_graphql_introspection(self, url: str):
        """
        Test for GraphQL introspection enabled
        """
        if 'graphql' not in url.lower():
            return
        
        introspection_query = '''
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
          }
        }
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
          }
        }
        '''
        
        try:
            response = await self.http_client.post(
                url,
                json={'query': introspection_query},
                headers={'Content-Type': 'application/json'}
            )
            
            if response and response.status == 200:
                text = await response.text()
                
                if '__schema' in text and 'types' in text:
                    self.findings.append({
                        'type': 'graphql_introspection',
                        'url': url,
                        'severity': 'medium',
                        'description': "GraphQL introspection is enabled, exposing schema details",
                        'remediation': "Disable introspection in production using graphql-disable-introspection or similar."
                    })
                    
        except Exception as e:
            logger.debug(f"GraphQL test error: {e}")
    
    async def test_api_authentication(self, url: str):
        """
        Test for weak API authentication
        """
        # Test without authentication
        try:
            response = await self.http_client.get(url)
            
            if response and response.status == 200:
                # Check if this should require auth
                text = await response.text()
                
                # Look for sensitive data patterns
                sensitive_patterns = ['password', 'email', 'phone', 'ssn', 'credit_card']
                
                if any(p in text.lower() for p in sensitive_patterns):
                    self.findings.append({
                        'type': 'unauthenticated_api_access',
                        'url': url,
                        'severity': 'high',
                        'description': "API endpoint accessible without authentication, exposes sensitive data",
                        'remediation': "Implement proper API authentication using OAuth 2.0, JWT, or API keys."
                    })
                    
        except Exception:
            pass
    
    async def test_rate_limiting(self, url: str):
        """
        Test for missing rate limiting
        """
        requests = []
        for i in range(20):
            requests.append(self.http_client.get(url))
        
        responses = await asyncio.gather(*requests, return_exceptions=True)
        
        # Count successful responses
        success_count = sum(
            1 for r in responses 
            if isinstance(r, Exception) == False and r and r.status == 200
        )
        
        if success_count >= 19:  # All or almost all succeeded
            self.findings.append({
                'type': 'missing_rate_limiting',
                'url': url,
                'severity': 'medium',
                'description': "No rate limiting detected on API endpoint",
                'remediation': "Implement rate limiting using Redis or API gateway."
            })