"""Vulnerability Detection Modules"""
from .injection_detector import InjectionDetector
from .xss_detector import XSSDetector
from .auth_detector import AuthDetector
from .config_detector import ConfigDetector
from .api_detector import APIDetector
from .privilege_escalation import PrivilegeEscalationTester
from .session_hijacking import SessionSecurityTester
from .automated_exploitation import AutomatedExploitation

__all__ = [
    'InjectionDetector',
    'XSSDetector', 
    'AuthDetector',
    'ConfigDetector',
    'APIDetector',
    'PrivilegeEscalationTester',
    'SessionSecurityTester',
    'AutomatedExploitation'
]