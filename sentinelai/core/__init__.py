"""SentinelAI Core Module"""
from .http_client import AsyncHTTPClient
from .crawler import WebCrawler

def __getattr__(name):
    if name == "SecurityScanner":
        from .scanner import SecurityScanner
        return SecurityScanner
    raise AttributeError(f"module {__name__} has no attribute {name}")

__all__ = ["WebCrawler", "AsyncHTTPClient", "SecurityScanner"]
