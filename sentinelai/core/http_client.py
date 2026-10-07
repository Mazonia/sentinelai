"""
Async HTTP Client with advanced features for security scanning
"""
import asyncio
import aiohttp
import ssl
import certifi
from typing import Dict, Optional, Any, List
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger(__name__)


class CachedResponse:
    def __init__(self, status: int, headers: dict, body_bytes: bytes, cookies=None):
        self.status = status
        self.headers = headers
        self._body_bytes = body_bytes
        self.cookies = cookies if cookies is not None else {}
        
    async def text(self) -> str:
        return self._body_bytes.decode('utf-8', errors='ignore')
        
    async def json(self) -> Any:
        import json
        return json.loads(self._body_bytes.decode('utf-8', errors='ignore'))
        
    async def read(self) -> bytes:
        return self._body_bytes
        
    def close(self):
        pass


class AsyncHTTPClient:
    """
    High-performance async HTTP client optimized for security scanning
    """
    
    def __init__(
        self,
        timeout: int = 30,
        max_concurrent: int = 100,
        custom_headers: Optional[Dict] = None,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        proxy: Optional[str] = None
    ):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.custom_headers = custom_headers or {}
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        
        # SSL context
        self.ssl_context = ssl.create_default_context(cafile=certifi.where()) if verify_ssl else False
        
        self._session: Optional[aiohttp.ClientSession] = None
        self._request_count = 0
        self._response_times: List[float] = []
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=100,
                limit_per_host=30,
                ssl=self.ssl_context,
                enable_cleanup_closed=True,
                force_close=True,
            )
            
            headers = {
                'User-Agent': 'SentinelAI Security Scanner/1.0 (Authorized Security Testing)',
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                **self.custom_headers
            }
            
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers=headers
            )
        
        return self._session
    
    async def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[CachedResponse]:
        """
        Make HTTP request with rate limiting, error handling, and leak-proof connection release
        """
        async with self.semaphore:
            session = await self._get_session()
            
            try:
                import time
                start_time = time.time()
                
                req_redirects = kwargs.pop('allow_redirects', self.follow_redirects)
                req_proxy = kwargs.pop('proxy', self.proxy)
                req_ssl = kwargs.pop('ssl', self.ssl_context if self.verify_ssl else False)
                
                response = await session.request(
                    method=method,
                    url=url,
                    allow_redirects=req_redirects,
                    proxy=req_proxy,
                    ssl=req_ssl,
                    **kwargs
                )
                
                self._response_times.append(time.time() - start_time)
                self._request_count += 1
                
                if response:
                    try:
                        body_bytes = await response.read()
                        headers_dict = dict(response.headers)
                        status_code = response.status
                        cookies_obj = response.cookies
                        response.close()  # Immediately release connection to pool
                        return CachedResponse(status_code, headers_dict, body_bytes, cookies_obj)
                    except Exception as re:
                        logger.debug(f"Error reading response for {url}: {re}")
                        try:
                            response.close()
                        except Exception:
                            pass
                
            except asyncio.TimeoutError:
                logger.warning(f"Timeout requesting {url}")
            except aiohttp.ClientError as e:
                logger.debug(f"Client error for {url}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error requesting {url}: {e}")
            
            return None
    
    async def get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Convenience method for GET requests"""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Convenience method for POST requests"""
        return await self.request('POST', url, **kwargs)
    
    async def test_payload(
        self,
        url: str,
        method: str = 'GET',
        payload: Optional[str] = None,
        parameter: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Test a specific payload and return detailed response info
        """
        result = {
            'url': url,
            'method': method,
            'payload': payload,
            'parameter': parameter,
            'status': None,
            'response_time': None,
            'content_length': None,
            'headers': {},
            'error': None,
            'indicators': []
        }
        
        try:
            import time
            start = time.time()
            
            if method.upper() == 'GET' and payload and parameter:
                from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[parameter] = [payload]
                new_query = urlencode(params, doseq=True)
                url = urlunparse(parsed._replace(query=new_query))
                response = await self.request(method, url, **kwargs)
            elif method.upper() == 'POST' and payload:
                data = {parameter: payload} if parameter else payload
                response = await self.request(method, url, data=data, **kwargs)
            else:
                response = await self.request(method, url, **kwargs)
            
            result['response_time'] = time.time() - start
            
            if response:
                result['status'] = response.status
                result['headers'] = dict(response.headers)
                body = await response.text()
                result['content_length'] = len(body)
                
                # Check for error indicators
                error_indicators = [
                    'sql syntax', 'mysql_fetch', 'pg_query', 'ora-',
                    'syntax error', 'warning:', 'fatal error',
                    'exception', 'stack trace', 'traceback'
                ]
                body_lower = body.lower()
                for indicator in error_indicators:
                    if indicator in body_lower:
                        result['indicators'].append(indicator)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    async def close(self):
        """Close the session"""
        if self._session and not self._session.closed:
            await self._session.close()
    
    def get_stats(self) -> Dict:
        """Get client statistics"""
        avg_response_time = sum(self._response_times) / len(self._response_times) if self._response_times else 0
        return {
            'total_requests': self._request_count,
            'avg_response_time': avg_response_time,
            'max_concurrent': self.semaphore._bound_value
        }