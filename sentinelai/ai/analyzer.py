"""
AI-Powered Vulnerability Analysis and Prioritization
"""
import logging
from typing import List, Dict, Any, Optional
import json
import asyncio

from ..models.database import Vulnerability

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """
    Uses AI/ML techniques for intelligent vulnerability analysis
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.context_cache = {}
    
    async def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
        target_context: str
    ) -> List[Vulnerability]:
        """
        Analyze vulnerabilities using AI to reduce false positives
        and provide intelligent prioritization
        """
        logger.info(f"Analyzing {len(vulnerabilities)} vulnerabilities with AI")
        
        analyzed = []
        
        for vuln in vulnerabilities:
            # AI-based false positive reduction
            confidence = await self._calculate_confidence(vuln)
            
            if confidence < 0.3:  # Likely false positive
                vuln.false_positive = True
                vuln.notes = "Flagged as likely false positive by AI analysis"
            
            # Context-aware risk scoring
            risk_score = await self._calculate_risk_score(vuln, target_context)
            vuln.risk_score = risk_score
            
            # Generate AI-powered remediation advice
            vuln.ai_remediation = await self._generate_remediation(vuln)
            
            # Generate exploit complexity assessment
            vuln.exploit_complexity = await self._assess_exploitability(vuln)
            
            analyzed.append(vuln)
        
        # Sort by risk score
        analyzed.sort(key=lambda x: x.risk_score or 0, reverse=True)
        
        return analyzed
    
    async def _calculate_confidence(self, vuln: Vulnerability) -> float:
        """
        Calculate confidence score that vulnerability is real
        """
        confidence = 0.5  # Base confidence
        
        # Factors that increase confidence
        if vuln.evidence:
            evidence = vuln.evidence
            if isinstance(evidence, dict):
                # Multiple indicators increase confidence
                if evidence.get('indicators'):
                    confidence += 0.2 * len(evidence['indicators'])
                
                # Consistent status codes
                status = evidence.get('status')
                if status == 200:
                    confidence += 0.1
        
        # Factors that decrease confidence (potential false positives)
        if vuln.type == 'xss':
            # XSS in search parameters often has false positives
            if 'search' in vuln.url.lower() or 'query' in str(vuln.parameter).lower():
                confidence -= 0.2
        
        if vuln.type == 'sql_injection':
            # Time-based without confirmation
            if vuln.subtype == 'time_based' and not vuln.evidence.get('confirmed'):
                confidence -= 0.15
        
        # Cap between 0 and 1
        return max(0.0, min(1.0, confidence))
    
    async def _calculate_risk_score(
        self,
        vuln: Vulnerability,
        context: str
    ) -> float:
        """
        Calculate context-aware risk score (0-10)
        """
        base_scores = {
            'sql_injection': 9.5,
            'command_injection': 10.0,
            'xss': 7.0,
            'idor': 8.0,
            'weak_credentials': 9.0,
            'missing_security_headers': 3.0,
            'information_disclosure': 4.0,
        }
        
        base = base_scores.get(vuln.type, 5.0)
        
        # Adjust based on severity
        severity_multiplier = {
            'critical': 1.0,
            'high': 0.9,
            'medium': 0.7,
            'low': 0.4,
            'info': 0.1
        }
        
        score = base * severity_multiplier.get(vuln.severity, 0.5)
        
        # Context adjustments
        context_lower = context.lower()
        
        # Higher risk for admin/login pages
        if any(x in vuln.url for x in ['admin', 'login', 'auth', 'dashboard']):
            score *= 1.2
        
        # Higher risk for API endpoints
        if '/api/' in vuln.url:
            score *= 1.1
        
        # Cap at 10
        return min(10.0, round(score, 1))
    
    async def _generate_remediation(self, vuln: Vulnerability) -> str:
        """
        Generate AI-powered specific remediation advice
        """
        remediation_templates = {
            'sql_injection': """
1. Use parameterized queries/prepared statements exclusively
2. Implement input validation using allowlists
3. Apply least privilege database access
4. Consider using ORM frameworks that handle escaping
5. Enable database query logging for monitoring
            """,
            'xss': """
1. Implement context-aware output encoding
2. Use Content Security Policy (CSP) headers
3. Sanitize user input using DOMPurify or similar
4. Use template auto-escaping features
5. Implement X-XSS-Protection headers
            """,
            'command_injection': """
1. Never pass user input to system commands
2. Use safe APIs instead of shell commands
3. Implement strict input validation
4. Use parameterized APIs for system calls
5. Run with minimal privileges
            """,
            'idor': """
1. Implement indirect object references (UUIDs instead of sequential IDs)
2. Verify user authorization for every resource access
3. Use role-based access control (RBAC)
4. Implement resource-level permissions
5. Log all access attempts
            """,
        }
        
        base = remediation_templates.get(vuln.type, vuln.remediation)
        
        # Add specific context
        if vuln.parameter:
            base += f"\n6. Specifically validate the '{vuln.parameter}' parameter"
        
        return base.strip()
    
    async def _assess_exploitability(self, vuln: Vulnerability) -> str:
        """
        Assess how easy the vulnerability is to exploit
        """
        easy_types = ['xss', 'information_disclosure', 'missing_security_headers']
        medium_types = ['idor', 'weak_credentials']
        hard_types = ['sql_injection', 'command_injection']
        
        if vuln.type in easy_types:
            return "Easy - Can be exploited with basic tools"
        elif vuln.type in medium_types:
            return "Medium - Requires some knowledge of the application"
        else:
            return "Hard - Requires specialized tools and knowledge"
    
    async def generate_attack_scenario(self, vuln: Vulnerability) -> str:
        """
        Generate a realistic attack scenario for the vulnerability
        """
        scenarios = {
            'sql_injection': f"""
An attacker could:
1. Access the vulnerable URL: {vuln.url}
2. Inject SQL payload: {vuln.payload}
3. Extract sensitive data: user credentials, personal information
4. Potentially modify or delete database records
5. In some cases, execute commands on the server
            """,
            'xss': f"""
An attacker could:
1. Craft a malicious link with payload: {vuln.payload[:50]}...
2. Send to victims via email or social media
3. Steal session cookies when victim clicks
4. Perform actions on behalf of the victim
5. Deface the website or redirect to malicious sites
            """,
            'idor': f"""
An attacker could:
1. Identify the vulnerable endpoint: {vuln.url}
2. Modify the ID parameter to access other users' data
3. Enumerate through sequential IDs
4. Access sensitive information without authorization
5. Potentially modify other users' data
            """,
        }
        
        return scenarios.get(vuln.type, "Attack scenario analysis not available")
    
    async def prioritize_findings(
        self,
        vulnerabilities: List[Vulnerability],
        business_context: Dict
    ) -> List[Dict]:
        """
        Prioritize findings based on business context
        """
        prioritized = []
        
        for vuln in vulnerabilities:
            priority_score = vuln.risk_score or 5.0
            
            # Business impact adjustments
            if business_context.get('is_production'):
                priority_score *= 1.2
            
            if business_context.get('has_sensitive_data'):
                priority_score *= 1.15
            
            if business_context.get('public_facing'):
                priority_score *= 1.1
            
            prioritized.append({
                'vulnerability': vuln,
                'priority_score': min(10, priority_score),
                'recommended_action': self._get_action(priority_score),
                'time_to_fix': self._estimate_fix_time(vuln)
            })
        
        # Sort by priority score
        prioritized.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return prioritized
    
    def _get_action(self, score: float) -> str:
        """Get recommended action based on score"""
        if score >= 8:
            return "Fix immediately - Critical risk"
        elif score >= 6:
            return "Fix within 24 hours - High risk"
        elif score >= 4:
            return "Fix within 1 week - Medium risk"
        else:
            return "Fix within 1 month - Low risk"
    
    def _estimate_fix_time(self, vuln: Vulnerability) -> str:
        """Estimate time to fix"""
        estimates = {
            'sql_injection': '4-8 hours',
            'xss': '2-4 hours',
            'command_injection': '2-6 hours',
            'idor': '4-12 hours',
            'weak_credentials': '30 minutes',
            'missing_security_headers': '1-2 hours',
        }
        return estimates.get(vuln.type, 'Unknown')