# xss_hunter/tests/conftest.py
"""
Pytest configuration and fixtures for XSS Hunter tests
"""

import pytest
import responses
from xss_hunter.core.reflection_detector import ReflectionDetector


@pytest.fixture(scope="session")
def test_endpoint():
    """Provide test endpoint URL"""
    return "https://api.example.com"


@pytest.fixture
def detector():
    """Provide detector instance for tests"""
    return ReflectionDetector(timeout=10, verify_ssl=False)


@pytest.fixture
def mock_responses():
    """Provide responses context manager"""
    with responses.RequestsMock() as rsps:
        yield rsps
