"""
Unit and Integration Tests for SentinelAI
"""
import pytest
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinelai.modules.arsenal import ToolArsenal, ARSENAL_CATEGORIES
from sentinelai.modules.recon_detector import ReconDetector, WAF_SIGNATURES
from sentinelai.modules.dir_fuzzer import DirFuzzer, COMMON_PATHS
from sentinelai.modules.cors_ssrf_detector import CORSSSRFDetector
from sentinelai.modules.traversal_detector import PathTraversalDetector
from sentinelai.utils.report_generator import ReportGenerator
from sentinelai.ai.cli_analyzer import CLIAnalyzer


def test_arsenal_tools():
    """Verify Tool Arsenal contains populated categories and tools"""
    tools = ToolArsenal.get_all_tools()
    assert len(tools) >= 15
    categories = list(ARSENAL_CATEGORIES.keys())
    assert len(categories) >= 5
    
    # Check essential tools are registered
    tool_names = [t["name"].lower() for t in tools]
    assert "nmap" in tool_names
    assert "sqlmap" in tool_names
    assert "nikto" in tool_names


def test_waf_signatures():
    """Verify WAF signatures are defined"""
    assert "Cloudflare" in WAF_SIGNATURES
    assert any("AWS" in k for k in WAF_SIGNATURES)
    assert any("Akamai" in k for k in WAF_SIGNATURES)


def test_dir_fuzzer_paths():
    """Verify common paths for directory fuzzing are defined"""
    assert len(COMMON_PATHS) >= 30
    assert "/.env" in COMMON_PATHS
    assert "/robots.txt" in COMMON_PATHS
    assert "/admin" in COMMON_PATHS


def test_report_generator():
    """Test generating HTML, Markdown, and JSON audit reports"""
    mock_scan_data = {
        "target": "https://test-target.local",
        "recon": {
            "target": "https://test-target.local",
            "host_ip": "127.0.0.1",
            "waf": "Cloudflare",
            "open_ports": [{"port": 80, "service": "HTTP", "state": "open"}],
            "subdomains": ["api.test-target.local"]
        },
        "findings": [
            {
                "type": "sql_injection",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "url": "https://test-target.local/search?q=1",
                "parameter": "q",
                "evidence": "SQL syntax error near '",
                "description": "SQL Injection in parameter q",
                "remediation": "Use parameterized queries",
                "code_patch": "cursor.execute('SELECT * FROM users WHERE q = %s', (q,))"
            },
            {
                "type": "missing_security_headers",
                "severity": "LOW",
                "cvss_score": 4.3,
                "url": "https://test-target.local",
                "parameter": "HSTS",
                "evidence": "Strict-Transport-Security header missing",
                "description": "Missing HSTS",
                "remediation": "Enable HSTS in web server",
                "code_patch": "add_header Strict-Transport-Security 'max-age=31536000;' always;"
            }
        ],
        "threat_model": {
            "overall_risk_rating": "CRITICAL",
            "executive_summary": "High risk detected due to unparameterized queries.",
            "primary_threat_vectors": ["SQL injection on query parameter"],
            "immediate_actions": ["Migrate to parameterized statements"]
        }
    }

    # Test instance methods
    reporter = ReportGenerator(mock_scan_data)
    html_content = reporter.generate_html()
    assert "https://test-target.local" in html_content
    assert "CRITICAL" in html_content
    assert "sql_injection" in html_content
    assert "AI Executive Threat Model" in html_content

    md_content = reporter.generate_markdown()
    assert "https://test-target.local" in md_content
    assert "9.8" in md_content
    assert "Developer Code Patch" in md_content

    json_content = reporter.generate_json()
    assert "test-target.local" in json_content

    # Test static style calls
    static_json = ReportGenerator.generate_json(mock_scan_data)
    assert "test-target.local" in static_json


def test_cli_analyzer_baseline():
    """Test heuristic baseline analyzer provides CVSS scores and remediations"""
    analyzer = CLIAnalyzer()
    mock_finding = {
        "type": "sql_injection",
        "severity": "CRITICAL",
        "parameter": "id"
    }
    baseline = analyzer._heuristic_baseline(mock_finding)
    assert baseline["cvss_score"] >= 8.0
    assert "parameterized" in baseline["remediation"].lower()
    assert "code_patch" in baseline


@pytest.mark.asyncio
async def test_cli_analyzer_threat_model():
    """Verify threat modeling generates risk rating, executive summary, and actionable roadmap"""
    analyzer = CLIAnalyzer()
    mock_recon = {
        "hostname": "vuln-target.local",
        "ip_addresses": ["192.168.1.100"],
        "waf": None,
        "open_ports": [{"port": 80, "service": "HTTP"}, {"port": 3306, "service": "MySQL"}],
        "technologies": ["PHP", "Apache", "MySQL"]
    }
    mock_findings = [
        {"type": "sql_injection", "severity": "CRITICAL", "parameter": "id", "url": "https://vuln-target.local/item"}
    ]
    threat_model = await analyzer.generate_threat_model("https://vuln-target.local", mock_recon, mock_findings)
    assert threat_model["overall_risk_rating"] in ["CRITICAL", "HIGH", "MEDIUM"]
    assert "executive_summary" in threat_model
    assert len(threat_model["primary_threat_vectors"]) >= 1
    assert len(threat_model["immediate_actions"]) >= 1
    assert len(threat_model["strategic_roadmap"]) >= 1


@pytest.mark.asyncio
async def test_cli_analyzer_copilot():
    """Verify Interactive Copilot delivers security advice and code patterns"""
    analyzer = CLIAnalyzer()
    session_ctx = {
        "target": "https://test.local",
        "findings": [{"type": "sql_injection", "severity": "CRITICAL"}],
        "recon": {"waf": "Cloudflare", "open_ports": [{"port": 443}]}
    }
    # Test SQL Injection advisory
    reply_sql = await analyzer.chat_copilot("How do I fix SQL injection in Python?", session_ctx)
    assert "parameterized" in reply_sql.lower() or "sql" in reply_sql.lower()

    # Test Security Headers advisory
    reply_headers = await analyzer.chat_copilot("What are recommended security headers?")
    assert "strict-transport-security" in reply_headers.lower() or "header" in reply_headers.lower()


@pytest.mark.asyncio
async def test_cli_analyzer_enrichment():
    """Verify analyze_findings enriches findings with CVSS 3.1 vectors and code patches"""
    analyzer = CLIAnalyzer()
    raw_findings = [
        {"type": "sql_injection", "severity": "CRITICAL", "parameter": "user_id"},
        {"type": "path_traversal", "severity": "HIGH", "parameter": "file"}
    ]
    enriched = await analyzer.analyze_findings(raw_findings)
    assert len(enriched) == 2
    for item in enriched:
        assert "cvss_score" in item
        assert "cvss_vector" in item
        assert "code_patch" in item
        assert "CVSS:3.1" in item["cvss_vector"]


@pytest.mark.asyncio
async def test_api_routes():
    """Test FastAPI application route definitions"""
    from sentinelai.api.main import app
    route_paths = [r.path for r in app.routes]
    assert "/api/v1/tools" in route_paths
    assert "/api/v1/recon/{domain}" in route_paths
    assert "/api/v1/fuzz" in route_paths
    assert "/api/v1/reports" in route_paths
    assert "/api/v1/quick-scan" in route_paths


def test_dashboard_target_memory():
    """Verify InteractiveDashboard stores and recalls session targets"""
    from sentinelai.cli.menu import InteractiveDashboard
    InteractiveDashboard.session_target = "https://memorized-target.local"
    assert InteractiveDashboard.session_target == "https://memorized-target.local"


def test_cli_help(capsys):
    """Verify CLI print_help displays commands and usage"""
    from sentinelai.cli.main import print_help
    print_help()
    captured = capsys.readouterr()
    assert "sentinelai" in captured.out
    assert "scan" in captured.out
    assert "recon" in captured.out
    assert "fuzz" in captured.out


def test_arsenal_categories_and_modes():
    """Verify expanded arsenal has 10 categories, presets, and pip packages"""
    tools = ToolArsenal.get_all_tools()
    assert len(tools) >= 25
    assert len(ARSENAL_CATEGORIES) == 10

    pip_tools = [t for t in tools if t.get("pip_pkg")]
    assert len(pip_tools) >= 8

    # Check presets
    for t in tools:
        assert "preset" in t
        assert "desc" in t


def test_scanner_specialized_workflows():
    """Verify StandaloneScanner supports multi-task workflows"""
    from sentinelai.core.standalone_scanner import StandaloneScanner
    scanner = StandaloneScanner()
    assert hasattr(scanner, "run_perimeter_recon")
    assert hasattr(scanner, "run_content_discovery")
    assert hasattr(scanner, "run_api_discovery")
    assert hasattr(scanner, "run_full_scan")


def test_windows_cross_platform_arsenal():
    """Verify arsenal tools include Windows-specific guides and smart executable resolution"""
    tools = ToolArsenal.get_all_tools()
    assert len(tools) >= 25
    for t in tools:
        assert "install_win" in t, f"Tool {t['name']} missing install_win"
        assert "install_linux" in t, f"Tool {t['name']} missing install_linux"

    # Test smart executable resolver finds python
    python_exe = ToolArsenal.find_tool_executable("python")
    assert python_exe is not None


def test_celery_windows_pool_config():
    """Verify Celery configures solo pool on Windows to avoid fork errors"""
    from sentinelai.automation.scheduler import celery_app
    if sys.platform == "win32":
        assert celery_app.conf.worker_pool == "solo"
