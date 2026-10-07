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
                "remediation": "Use parameterized queries"
            },
            {
                "type": "missing_security_headers",
                "severity": "LOW",
                "cvss_score": 4.3,
                "url": "https://test-target.local",
                "parameter": "HSTS",
                "evidence": "Strict-Transport-Security header missing",
                "description": "Missing HSTS",
                "remediation": "Enable HSTS in web server"
            }
        ]
    }

    # Test instance methods
    reporter = ReportGenerator(mock_scan_data)
    html_content = reporter.generate_html()
    assert "https://test-target.local" in html_content
    assert "CRITICAL" in html_content
    assert "sql_injection" in html_content

    md_content = reporter.generate_markdown()
    assert "https://test-target.local" in md_content
    assert "9.8" in md_content

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
