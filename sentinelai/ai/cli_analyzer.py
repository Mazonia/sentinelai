"""
AI Vulnerability Analysis & Remediation Engine
Supports Groq (Llama-3.3-70b), Venice, OpenAI, and Local Heuristic Engine.
"""
import os
import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class CLIAnalyzer:
    """
    Intelligent CVSS 3.1 Scoring, False-Positive Reduction, and Remediation Engine
    """

    def __init__(self):
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.venice_api_key = os.getenv("VENICE_API_KEY")

    async def analyze_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze and enrich scan findings with AI remediation and CVSS scores"""
        analyzed = []
        for item in findings:
            enriched = dict(item)
            baseline = self._heuristic_baseline(enriched)
            enriched.update(baseline)

            if self.groq_api_key or self.openai_api_key or self.venice_api_key:
                ai_patch = await self._query_llm(enriched)
                if ai_patch:
                    enriched["remediation"] = ai_patch.get("remediation", enriched.get("remediation"))
                    enriched["cvss_score"] = ai_patch.get("cvss_score", enriched.get("cvss_score"))
                    enriched["ai_explanation"] = ai_patch.get("explanation", "")
                    enriched["confidence"] = ai_patch.get("confidence", enriched.get("confidence", 0.9))

            analyzed.append(enriched)
        return analyzed

    def _heuristic_baseline(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Local offline rule-based security scoring & remediation"""
        v_type = str(finding.get("type", "")).lower()
        title = str(finding.get("title", "")).lower()

        if "sql" in v_type or "sql" in title or "injection" in v_type:
            return {
                "severity": "CRITICAL",
                "cvss_score": 9.3,
                "confidence": 0.95,
                "remediation": "Use parameterized queries / prepared statements (e.g., PDO in PHP, parameterized SQL in Python, PreparedStatement in Java). Avoid string concatenation in queries.",
                "cwe": "CWE-89: SQL Injection"
            }
        elif "xss" in v_type or "xss" in title or "cross-site scripting" in title:
            return {
                "severity": "HIGH",
                "cvss_score": 7.5,
                "confidence": 0.90,
                "remediation": "Context-aware output encoding (HTML, JavaScript, Attribute context) and enforce a strict Content Security Policy (CSP). Use modern reactive frameworks that escape text by default.",
                "cwe": "CWE-79: Cross-Site Scripting (XSS)"
            }
        elif "ssrf" in v_type or "server-side request forgery" in title:
            return {
                "severity": "HIGH",
                "cvss_score": 8.6,
                "confidence": 0.92,
                "remediation": "Implement an allowlist of approved domains and protocols. Validate and reject requests targeting internal network ranges (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16, 169.254.169.254).",
                "cwe": "CWE-918: Server-Side Request Forgery (SSRF)"
            }
        elif "cors" in v_type or "cors" in title:
            return {
                "severity": "MEDIUM",
                "cvss_score": 6.5,
                "confidence": 0.88,
                "remediation": "Remove 'Access-Control-Allow-Origin: *' when credentials are accepted. Explicitly configure trusted origin domains rather than reflecting arbitrary Origin request headers.",
                "cwe": "CWE-942: Overly Permissive CORS Policy"
            }
        elif "header" in v_type or "hsts" in title or "csp" in title or "clickjacking" in title:
            return {
                "severity": "LOW",
                "cvss_score": 4.3,
                "confidence": 0.95,
                "remediation": "Add security headers to server configuration: Strict-Transport-Security: max-age=31536000; includeSubDomains, Content-Security-Policy, X-Frame-Options: DENY, and X-Content-Type-Options: nosniff.",
                "cwe": "CWE-16: Configuration"
            }
        else:
            return {
                "severity": finding.get("severity", "MEDIUM"),
                "cvss_score": finding.get("cvss_score", 5.0),
                "confidence": 0.80,
                "remediation": "Review application input handling, enforce least privilege access controls, and sanitize untrusted client inputs.",
                "cwe": "CWE-20: Improper Input Validation"
            }

    async def _query_llm(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Query LLM provider for deep vulnerability analysis"""
        import aiohttp
        prompt = (
            f"Vulnerability Type: {finding.get('type')}\n"
            f"URL: {finding.get('url')}\n"
            f"Parameter: {finding.get('parameter')}\n"
            f"Evidence: {str(finding.get('evidence'))[:200]}\n\n"
            'Respond ONLY with valid JSON: {"cvss_score": 7.5, "remediation": "Exact fix code/instructions", "confidence": 0.95, "explanation": "Why this is vulnerable"}'
        )

        headers = {}
        url = ""
        payload = {}

        if self.groq_api_key:
            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {"Authorization": f"Bearer {self.groq_api_key}", "Content-Type": "application/json"}
            payload = {
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "system", "content": "You are SentinelAI Security Auditor."}, {"role": "user", "content": prompt}],
                "temperature": 0.1
            }
        elif self.openai_api_key:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {self.openai_api_key}", "Content-Type": "application/json"}
            payload = {
                "model": "gpt-4o-mini",
                "messages": [{"role": "system", "content": "You are SentinelAI Security Auditor."}, {"role": "user", "content": prompt}],
                "temperature": 0.1
            }

        if url:
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(url, headers=headers, json=payload) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            content = data["choices"][0]["message"]["content"]
                            clean_json = content.replace("```json", "").replace("```", "").strip()
                            return json.loads(clean_json)
            except Exception:
                pass
        return None
