# config/__init__.py
"""
XSS Hunter Configuration Module

This module provides access to all configuration files and settings.
"""

# Make key configuration classes available at package level
from .settings import Settings
from .payloads import load_payloads
from .default_headers import DEFAULT_HEADERS

__all__ = [
    'Settings',
    'load_payloads', 
    'DEFAULT_HEADERS'
]

__version__ = "1.0.0"
