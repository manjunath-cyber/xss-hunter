# xss_hunter/core/__init__.py
"""
XSS Hunter Core Module
Provides core XSS detection and scanning functionality for the Cyber API Platform.
"""

from .scanners import XSSScanner
from .payloads import PayloadGenerator
from .validators import XSSValidator
from .reporters import VulnerabilityReporter

__all__ = [
    'XSSScanner',
    'PayloadGenerator',
    'XSSValidator',
    'VulnerabilityReporter',
]

__version__ = '1.0.0'
