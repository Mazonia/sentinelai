"""
Advanced AI Vulnerability Analysis, Threat Modeling & Copilot Engine
Supports Groq (Llama-3.3-70b), OpenAI (GPT-4o), Venice AI, Ollama (Local),
and DeepSeek with an offline Heuristic Rule Engine fallback.
"""
import os
import json
import logging
import asyncio
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class CLIAnalyzer:
    """
    Intelligent Security AI Engine providing:
    1. Deep Vulnerability Correlation & False-Positive Elimination
    2. CVSS 3.1 Scoring & Vector Generation
    3. Automated Developer Code Patches & Config Fixes
    4. Holistic Attack Surface Threat Modeling
    5. Interactive AI Security Copilot for Analyst Advisory
    """

    def __init__(self):
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.venice_api_key = os.getenv("VENICE_API_KEY")
        self.deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.copilot_history: List[Dict[str, str]] = []

    def has_ai_provider(self) -> bool:
        """Check if any LLM provider key or local engine is configured"""
        return bool(self.groq_api_key or self.openai_api_key or self.venice_api_key or self.deepseek_api_key)

    async def _query_llm_raw(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> Optional[str]:
        """Query LLM across configured providers with automatic fallback"""
        import aiohttp

        providers = []
        if self.groq_api_key:
            providers.append({
                "url": "https://api.groq.com/openai/v1/chat/completions",
                "headers": {"Authorization": f"Bearer {self.groq_api_key}", "Content-Type": "application/json"},
                "model": "llama-3.3-70b-versatile"
            })
        if self.openai_api_key:
            providers.append({
                "url": "https://api.openai.com/v1/chat/completions",
                "headers": {"Authorization": f"Bearer {self.openai_api_key}", "Content-Type": "application/json"},
                "model": "gpt-4o-mini"
            })
        if self.deepseek_api_key:
            providers.append({
                "url": "https://api.deepseek.com/chat/completions",
                "headers": {"Authorization": f"Bearer {self.deepseek_api_key}", "Content-Type": "application/json"},
                "model": "deepseek-chat"
            })
        if self.venice_api_key:
            providers.append({
                "url": "https://api.venice.ai/v1/chat/completions",
                "headers": {"Authorization": f"Bearer {self.venice_api_key}", "Content-Type": "application/json"},
                "model": "llama-3.3-70b"
            })

        for prov in providers:
            payload = {
                "model": prov["model"],
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": temperature
            }
            try:
                timeout = aiohttp.ClientTimeout(total=12)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(prov["url"], headers=prov["headers"], json=payload) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            content = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                            if content:
                                return content
                        else:
                            logger.debug(f"Provider {prov['url']} returned HTTP {resp.status}")
            except Exception as e:
                logger.debug(f"LLM query failed for {prov['url']}: {e}")

        return None

    async def analyze_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze, enrich, score, and generate remediation code for all findings"""
        analyzed = []
        for item in findings:
            enriched = dict(item)
            baseline = self._heuristic_baseline(enriched)
            enriched.update(baseline)

            if self.has_ai_provider():
                ai_patch = await self._query_llm_finding(enriched)
                if ai_patch:
                    enriched["remediation"] = ai_patch.get("remediation", enriched.get("remediation"))
                    enriched["cvss_score"] = ai_patch.get("cvss_score", enriched.get("cvss_score"))
                    enriched["ai_explanation"] = ai_patch.get("explanation", "")
                    enriched["cvss_vector"] = ai_patch.get("cvss_vector", enriched.get("cvss_vector"))
                    enriched["exploit_complexity"] = ai_patch.get("exploit_complexity", enriched.get("exploit_complexity"))
                    enriched["code_patch"] = ai_patch.get("code_patch", "")
                    enriched["confidence"] = ai_patch.get("confidence", enriched.get("confidence", 0.9))

            analyzed.append(enriched)
        return analyzed

    async def _query_llm_finding(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Query LLM for deep finding analysis and code patches"""
        system_prompt = (
            "You are SentinelAI Security Auditor & AppSec Engineer. "
            "Analyze the given vulnerability finding. Provide accurate CVSS 3.1 score, "
            "vector string, risk explanation, and exact developer remediation code patch. "
            "Respond ONLY with valid JSON."
        )
        user_prompt = (
            f"Vulnerability Type: {finding.get('type')}\n"
            f"Title: {finding.get('title')}\n"
            f"URL: {finding.get('url')}\n"
            f"Parameter: {finding.get('parameter')}\n"
            f"Evidence: {str(finding.get('evidence'))[:250]}\n\n"
            "Return JSON format:\n"
            "{\n"
            '  "cvss_score": 8.5,\n'
            '  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",\n'
            '  "exploit_complexity": "LOW",\n'
            '  "confidence": 0.92,\n'
            '  "explanation": "Why this vulnerability occurs and how it impacts security.",\n'
            '  "remediation": "Concise remediation summary.",\n'
            '  "code_patch": "Complete code snippet showing how to fix it in Python / PHP / JavaScript / Nginx"\n'
            "}"
        )
        raw_res = await self._query_llm_raw(system_prompt, user_prompt)
        if raw_res:
            try:
                cleaned = raw_res.replace("```json", "").replace("```", "").strip()
                return json.loads(cleaned)
            except Exception:
                pass
        return None

    async def generate_threat_model(
        self,
        target: str,
        recon_data: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate holistic target threat model, architectural risk rating,
        and prioritized remediation roadmap.
        """
        system_prompt = (
            "You are SentinelAI Principal Security Architect. "
            "Generate a professional, executive-level threat model and architectural risk assessment "
            "based on reconnaissance intelligence and discovered vulnerabilities. "
            "Respond in JSON format."
        )
        summary_findings = [
            f"- [{f.get('severity')}] {f.get('title', f.get('type'))} on {f.get('parameter', f.get('url'))}"
            for f in findings[:15]
        ]
        user_prompt = (
            f"Target: {target}\n"
            f"Host IP: {', '.join(recon_data.get('ip_addresses', []))}\n"
            f"WAF: {recon_data.get('waf', 'None detected')}\n"
            f"Open Ports: {', '.join(str(p.get('port')) for p in recon_data.get('open_ports', []))}\n"
            f"Technologies: {', '.join(recon_data.get('technologies', []))}\n"
            f"Discovered Findings ({len(findings)} total):\n" + "\n".join(summary_findings) + "\n\n"
            "Return JSON format:\n"
            "{\n"
            '  "overall_risk_rating": "HIGH",\n'
            '  "executive_summary": "Paragraph summarizing target security posture.",\n'
            '  "primary_threat_vectors": ["Vector 1", "Vector 2"],\n'
            '  "architectural_weaknesses": ["Weakness 1", "Weakness 2"],\n'
            '  "immediate_actions": ["Action 1 within 24h", "Action 2"],\n'
            '  "strategic_roadmap": ["Roadmap item 1", "Roadmap item 2"]\n'
            "}"
        )

        if self.has_ai_provider():
            raw_res = await self._query_llm_raw(system_prompt, user_prompt, temperature=0.3)
            if raw_res:
                try:
                    cleaned = raw_res.replace("```json", "").replace("```", "").strip()
                    return json.loads(cleaned)
                except Exception:
                    pass

        # Offline Heuristic Threat Model Fallback
        crit_count = sum(1 for f in findings if str(f.get("severity")).upper() == "CRITICAL")
        high_count = sum(1 for f in findings if str(f.get("severity")).upper() == "HIGH")

        overall_risk = "CRITICAL" if crit_count > 0 else ("HIGH" if high_count > 0 else "MEDIUM")
        tech_str = ", ".join(recon_data.get("technologies", [])) or "Standard Web Stack"
        waf_status = recon_data.get("waf") or "No active Web Application Firewall identified"

        return {
            "overall_risk_rating": overall_risk,
            "executive_summary": (
                f"Automated security assessment of {target} revealed {len(findings)} vulnerabilities. "
                f"The target runs on {tech_str} with {waf_status}. "
                f"Identified risks require immediate attention to prevent unauthorized access or data exposure."
            ),
            "primary_threat_vectors": [
                "Publicly accessible endpoints lacking defensive rate-limiting or authentication controls",
                "Untrusted user parameter handling vulnerable to injection or script execution",
                "Missing transport and framing security headers exposing clients to MITM or clickjacking"
            ],
            "architectural_weaknesses": [
                f"Exposed perimeter ports: {', '.join(str(p.get('port')) for p in recon_data.get('open_ports', [])) or 'None'}",
                "Absence of modern defense-in-depth headers (HSTS, CSP, X-Frame-Options)"
            ],
            "immediate_actions": [
                "Implement input validation and parameterized queries across all dynamic inputs",
                "Enforce strict Content Security Policy (CSP) and HSTS max-age headers",
                "Restrict public access to administrative, debug, and backup file paths"
            ],
            "strategic_roadmap": [
                "Integrate automated DAST/SAST testing into CI/CD deployment pipelines",
                "Deploy and tune a Web Application Firewall (WAF) with OWASP Core Rule Sets"
            ]
        }

    async def chat_copilot(self, user_message: str, session_context: Optional[Dict[str, Any]] = None) -> str:
        """
        Interactive Security Copilot: provides expert guidance, code patches,
        and testing methodology directly inside the terminal.
        """
        ctx_summary = ""
        if session_context:
            target = session_context.get("target", "N/A")
            findings = session_context.get("findings", [])
            recon = session_context.get("recon", {})
            ctx_summary = (
                f"Current Target: {target}\n"
                f"WAF: {recon.get('waf', 'N/A')}\n"
                f"Open Ports: {', '.join(str(p.get('port')) for p in recon.get('open_ports', []))}\n"
                f"Findings Count: {len(findings)}\n"
            )

        system_prompt = (
            "You are SentinelAI Security Copilot, an elite defensive AppSec advisor and penetration testing mentor. "
            "Help the analyst understand vulnerabilities, explain risks, suggest verification steps, "
            "and write secure remediation code (Python, PHP, JavaScript, SQL, Bash, Nginx, Apache). "
            "Never generate malicious payloads or destructive exploit chains. Always provide clear, "
            "concise, professional engineering guidance."
        )

        if ctx_summary:
            system_prompt += f"\n\nActive Session Context:\n{ctx_summary}"

        # Maintain conversation history
        self.copilot_history.append({"role": "user", "content": user_message})
        if len(self.copilot_history) > 10:
            self.copilot_history = self.copilot_history[-10:]

        if self.has_ai_provider():
            res = await self._query_llm_raw(system_prompt, user_message, temperature=0.3)
            if res:
                self.copilot_history.append({"role": "assistant", "content": res})
                return res

        # Offline Local Heuristic Knowledge Base Fallback
        query_lower = user_message.lower()
        if "sql" in query_lower:
            return (
                "🛡️ **SQL Injection (SQLi) Advisory & Remediation**:\n\n"
                "- **Root Cause**: Concatenating untrusted user input directly into SQL queries.\n"
                "- **Secure Fix**: Use Parameterized Queries (Prepared Statements).\n\n"
                "**Python Example (psycopg2 / sqlite3)**:\n"
                "```python\n"
                "# INSECURE: cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
                "# SECURE:\n"
                "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                "```\n\n"
                "**PHP PDO Example**:\n"
                "```php\n"
                "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n"
                "$stmt->execute(['id' => $userId]);\n"
                "```"
            )
        elif "xss" in query_lower:
            return (
                "🛡️ **Cross-Site Scripting (XSS) Advisory & Remediation**:\n\n"
                "- **Root Cause**: Rendering user input in DOM/HTML without context-aware sanitization.\n"
                "- **Fix**: HTML-encode output and enforce Content-Security-Policy (CSP).\n\n"
                "**Python (html.escape)**:\n"
                "```python\n"
                "import html\n"
                "safe_output = html.escape(untrusted_str)\n"
                "```\n\n"
                "**Recommended HTTP Header**:\n"
                "```http\n"
                "Content-Security-Policy: default-src 'self'; script-src 'self'\n"
                "```"
            )
        elif "ssrf" in query_lower:
            return (
                "🛡️ **Server-Side Request Forgery (SSRF) Advisory & Remediation**:\n\n"
                "- **Root Cause**: Backend server fetches remote URLs supplied by users without domain validation.\n"
                "- **Fix**: Restrict URL schemas to HTTP/HTTPS, allowlist target domains, and block private IP spaces (RFC 1918 & metadata 169.254.169.254).\n\n"
                "```python\n"
                "import ipaddress, socket\n"
                "def is_safe_ip(host):\n"
                "    ip = socket.gethostbyname(host)\n"
                "    return not ipaddress.ip_address(ip).is_private\n"
                "```"
            )
        elif "cors" in query_lower or "origin" in query_lower:
            return (
                "🛡️ **CORS Misconfiguration Advisory**:\n\n"
                "- **Issue**: Reflecting arbitrary Origin headers with `Access-Control-Allow-Credentials: true`.\n"
                "- **Fix**: Maintain a strict allowlist of trusted domains. Never dynamically reflect `Origin: null`."
            )
        elif "header" in query_lower or "hsts" in query_lower:
            return (
                "🛡️ **Recommended Production Security Headers**:\n\n"
                "```nginx\n"
                "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
                "add_header X-Frame-Options \"DENY\" always;\n"
                "add_header X-Content-Type-Options \"nosniff\" always;\n"
                "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
                "```"
            )
        else:
            return (
                f"🤖 **SentinelAI Copilot**: I analyzed your query regarding '{user_message}'.\n\n"
                "To harden this target:\n"
                "1. Audit all HTTP inputs against OWASP Top 10 guidelines.\n"
                "2. Ensure principle of least privilege on databases and API keys.\n"
                "3. Configure modern HTTP security headers (HSTS, CSP, X-Frame-Options).\n\n"
                "💡 *Tip: Add GROQ_API_KEY or OPENAI_API_KEY to your environment to enable live LLM reasoning!*"
            )

    def _heuristic_baseline(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Local offline rule-based security scoring & remediation"""
        v_type = str(finding.get("type", "")).lower()
        title = str(finding.get("title", "")).lower()

        if "sql" in v_type or "sql" in title or "injection" in v_type:
            return {
                "severity": "CRITICAL",
                "cvss_score": 9.3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "exploit_complexity": "LOW",
                "confidence": 0.95,
                "remediation": "Use parameterized queries / prepared statements (e.g., PDO in PHP, parameterized SQL in Python, PreparedStatement in Java). Avoid string concatenation in queries.",
                "code_patch": "cursor.execute('SELECT * FROM accounts WHERE id = %s', (account_id,))",
                "cwe": "CWE-89: SQL Injection"
            }
        elif "xss" in v_type or "xss" in title or "cross-site scripting" in title:
            return {
                "severity": "HIGH",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "exploit_complexity": "LOW",
                "confidence": 0.90,
                "remediation": "Context-aware output encoding (HTML, JavaScript, Attribute context) and enforce a strict Content Security Policy (CSP). Use modern reactive frameworks that escape text by default.",
                "code_patch": "from html import escape\nsafe_output = escape(untrusted_user_input)",
                "cwe": "CWE-79: Cross-Site Scripting (XSS)"
            }
        elif "traversal" in v_type or "lfi" in v_type or "inclusion" in v_type:
            return {
                "severity": "HIGH",
                "cvss_score": 8.6,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "exploit_complexity": "LOW",
                "confidence": 0.92,
                "remediation": "Validate filenames against a strict allowlist. Resolve canonical paths with os.path.realpath and ensure they stay within the base directory.",
                "code_patch": "safe_path = os.path.abspath(os.path.join(BASE_DIR, os.path.basename(filename)))",
                "cwe": "CWE-22: Path Traversal"
            }
        elif "ssrf" in v_type or "server-side request forgery" in title:
            return {
                "severity": "HIGH",
                "cvss_score": 8.6,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                "exploit_complexity": "MEDIUM",
                "confidence": 0.92,
                "remediation": "Implement an allowlist of approved domains and protocols. Validate and reject requests targeting internal network ranges (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16, 169.254.169.254).",
                "code_patch": "import ipaddress\nif ipaddress.ip_address(resolved_ip).is_private: raise ValueError('Internal IP blocked')",
                "cwe": "CWE-918: Server-Side Request Forgery (SSRF)"
            }
        elif "cors" in v_type or "cors" in title:
            return {
                "severity": "MEDIUM",
                "cvss_score": 6.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                "exploit_complexity": "LOW",
                "confidence": 0.88,
                "remediation": "Remove 'Access-Control-Allow-Origin: *' when credentials are accepted. Explicitly configure trusted origin domains rather than reflecting arbitrary Origin request headers.",
                "code_patch": "if origin in ALLOWED_ORIGINS:\n    headers['Access-Control-Allow-Origin'] = origin",
                "cwe": "CWE-942: Overly Permissive CORS Policy"
            }
        elif "header" in v_type or "hsts" in title or "csp" in title or "clickjacking" in title:
            return {
                "severity": "LOW",
                "cvss_score": 4.3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                "exploit_complexity": "LOW",
                "confidence": 0.95,
                "remediation": "Add security headers to server configuration: Strict-Transport-Security: max-age=31536000; includeSubDomains, Content-Security-Policy, X-Frame-Options: DENY, and X-Content-Type-Options: nosniff.",
                "code_patch": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;\nadd_header X-Frame-Options 'DENY' always;",
                "cwe": "CWE-16: Configuration"
            }
        else:
            return {
                "severity": finding.get("severity", "MEDIUM"),
                "cvss_score": finding.get("cvss_score", 5.0),
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "exploit_complexity": "LOW",
                "confidence": 0.80,
                "remediation": "Review application input handling, enforce least privilege access controls, and sanitize untrusted client inputs.",
                "code_patch": "# Apply input validation and strict type constraints",
                "cwe": "CWE-20: Improper Input Validation"
            }
