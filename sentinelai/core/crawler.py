"""
Intelligent web crawler for discovering application endpoints
"""
import asyncio
import logging
from typing import Set, List, Optional, Dict
from urllib.parse import urljoin, urlparse, urldefrag
from bs4 import BeautifulSoup
import re

from .http_client import AsyncHTTPClient

logger = logging.getLogger(__name__)


class WebCrawler:
    """
    Advanced web crawler with JavaScript-aware capabilities
    """
    
    def __init__(
        self,
        http_client: AsyncHTTPClient,
        respect_robots: bool = False
    ):
        self.http_client = http_client
        self.respect_robots = respect_robots
        self.visited: Set[str] = set()
        self.discovered: Set[str] = set()
        self.forms: List[Dict] = []
        self.api_endpoints: Set[str] = set()
        
        # Common paths to check
        self.common_paths = [
            '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
            '/api/', '/api/v1/', '/api/v2/', '/graphql',
            '/admin/', '/login', '/register', '/dashboard',
            '/.env', '/.git/config', '/config.json', '/backup/',
            '/test/', '/dev/', '/staging/', '/api/docs', '/swagger.json'
        ]
    
    async def crawl(
        self,
        start_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        exclude_paths: Optional[List[str]] = None
    ) -> Set[str]:
        """
        Crawl website starting from start_url
        """
        exclude_paths = exclude_paths or []
        base_domain = urlparse(start_url).netloc
        
        # Queue: (url, depth)
        queue = asyncio.Queue()
        await queue.put((start_url, 0))
        self.discovered.add(start_url)
        
        tasks = []
        for _ in range(10):  # 10 concurrent crawlers
            task = asyncio.create_task(
                self._crawler_worker(queue, base_domain, max_depth, max_pages, exclude_paths)
            )
            tasks.append(task)
        
        await queue.join()
        
        # Cancel worker tasks
        for task in tasks:
            task.cancel()
        
        # Also check common paths
        await self._check_common_paths(start_url)
        
        return self.discovered
    
    async def _crawler_worker(
        self,
        queue: asyncio.Queue,
        base_domain: str,
        max_depth: int,
        max_pages: int,
        exclude_paths: List[str]
    ):
        """Worker to process URLs from queue"""
        while True:
            try:
                url, depth = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            
            try:
                if len(self.visited) >= max_pages:
                    continue
                
                if depth > max_depth:
                    continue
                
                normalized_url = self._normalize_url(url)
                if normalized_url in self.visited:
                    continue
                
                self.visited.add(normalized_url)
                logger.info(f"Crawling URL: {url} (depth: {depth})")
                
                # Fetch and parse
                response = await self.http_client.get(url)
                if not response:
                    logger.info(f"Failed to fetch {url} (connection timeout or SSL error)")
                    continue
                
                if response.status != 200:
                    logger.info(f"Failed to fetch {url} (HTTP status code {response.status})")
                    continue
                
                logger.info(f"Successfully fetched {url} (status: 200)")
                content_type = response.headers.get('Content-Type', '')
                
                if 'text/html' in content_type:
                    await self._parse_html(url, response, queue, depth, base_domain, exclude_paths)
                elif 'application/json' in content_type:
                    await self._parse_json_api(url, response)
                elif 'text/javascript' in content_type or 'application/javascript' in content_type:
                    await self._parse_javascript(url, response)
                
            except Exception as e:
                logger.info(f"Crawler error for {url}: {e}")
            finally:
                queue.task_done()
    
    async def _parse_html(
        self,
        url: str,
        response,
        queue: asyncio.Queue,
        depth: int,
        base_domain: str,
        exclude_paths: List[str]
    ):
        """Parse HTML and extract links, forms, and API endpoints"""
        try:
            text = await response.text()
            soup = BeautifulSoup(text, 'html.parser')
            
            # Extract links
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
                href = tag.get('href') or tag.get('src') or tag.get('action')
                if href:
                    absolute_url = urljoin(url, href)
                    normalized = self._normalize_url(absolute_url)
                    
                    if self._should_crawl(normalized, base_domain, exclude_paths):
                        if normalized not in self.discovered:
                            self.discovered.add(normalized)
                            await queue.put((normalized, depth + 1))
            
            # Extract forms
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': input_tag.get('name'),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    })
                self.forms.append(form_data)
            
            # Extract JavaScript API endpoints
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    self._extract_api_from_js(script.string, url)
                    
        except Exception as e:
            logger.debug(f"Parse error for {url}: {e}")
    
    async def _parse_json_api(self, url: str, response):
        """Parse JSON responses for API discovery"""
        try:
            text = await response.text()
            # Look for API patterns in JSON
            patterns = [
                r'["\']?api["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'["\']?endpoint["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'["\']?url["\']?\s*[:=]\s*["\']([^"\']+)["\']'
            ]
            for pattern in patterns:
                matches = re.findall(pattern, text)
                for match in matches:
                    absolute = urljoin(url, match)
                    self.api_endpoints.add(absolute)
        except Exception:
            pass
    
    async def _parse_javascript(self, url: str, response):
        """Parse JavaScript files for API endpoints"""
        try:
            text = await response.text()
            self._extract_api_from_js(text, url)
        except Exception:
            pass
    
    def _extract_api_from_js(self, js_code: str, base_url: str):
        """Extract API endpoints from JavaScript code"""
        patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
            r'\.ajax\({[^}]*url\s*:\s*["\']([^"\']+)["\']',
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'baseURL\s*[=:]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_code)
            for match in matches:
                if match.startswith('http'):
                    self.api_endpoints.add(match)
                else:
                    self.api_endpoints.add(urljoin(base_url, match))
    
    async def _check_common_paths(self, base_url: str):
        """Check common sensitive paths"""
        tasks = []
        for path in self.common_paths:
            url = urljoin(base_url, path)
            tasks.append(self._check_path(url))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _check_path(self, url: str):
        """Check if a specific path exists"""
        try:
            response = await self.http_client.get(url)
            if response and response.status in [200, 301, 302, 401, 403]:
                self.discovered.add(url)
        except Exception:
            pass
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for comparison"""
        url, _ = urldefrag(url)
        return url.rstrip('/')
    
    def _should_crawl(self, url: str, base_domain: str, exclude_paths: List[str]) -> bool:
        """Check if URL should be crawled"""
        parsed = urlparse(url)
        
        # Same domain only
        if parsed.netloc != base_domain:
            return False
        
        # Skip excluded paths
        for exclude in exclude_paths:
            if exclude in parsed.path:
                return False
        
        # Skip common non-web resources
        skip_extensions = ['.pdf', '.zip', '.tar', '.gz', '.jpg', '.png', '.gif', '.css', '.ico']
        if any(parsed.path.endswith(ext) for ext in skip_extensions):
            return False
        
        return True
    
    def get_forms(self) -> List[Dict]:
        """Get discovered forms"""
        return self.forms
    
    def get_api_endpoints(self) -> Set[str]:
        """Get discovered API endpoints"""
        return self.api_endpoints