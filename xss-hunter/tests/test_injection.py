# xss_hunter/tests/test_injector.py
"""
Comprehensive Test Suite for XSS Payload Injection Module
Tests payload generation, injection mechanisms, and payload variations.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any
from urllib.parse import urlencode, parse_qs, urlparse
import responses

from xss_hunter.core.reflection_detector import ReflectionDetector
from xss_hunter.utils.logger import setup_logging


# Setup logger for tests
setup_logging(log_level='DEBUG', log_dir='logs/tests')


class TestPayloadGeneration:
    """Test XSS payload generation and variations"""

    @pytest.fixture
    def detector(self):
        """Create detector with payload list"""
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_payload_list_completeness(self, detector):
        """Test that payload list covers major XSS vectors"""
        payloads = detector.test_payloads
        
        # Check for essential payload types
        assert any('<script>' in p.lower() for p in payloads), "Missing <script> payload"
        assert any('onerror' in p.lower() for p in payloads), "Missing onerror payload"
        assert any('onload' in p.lower() for p in payloads), "Missing onload payload"
        assert any('onfocus' in p.lower() for p in payloads), "Missing onfocus payload"
        assert any('onstart' in p.lower() for p in payloads), "Missing onstart payload"

    def test_payload_diversity(self, detector):
        """Test payload diversity for different attack vectors"""
        payloads = detector.test_payloads
        
        # Check different payload structures
        event_handlers = [p for p in payloads if 'on' in p and '=' in p]
        html_tags = [p for p in payloads if '<' in p]
        javascript = [p for p in payloads if 'javascript:' in p or 'alert' in p]
        
        assert len(event_handlers) > 0, "No event handler payloads"
        assert len(html_tags) > 0, "No HTML tag payloads"
        assert len(javascript) > 0, "No JavaScript payloads"

    def test_payload_validity(self, detector):
        """Test that all payloads are valid strings"""
        for payload in detector.test_payloads:
            assert isinstance(payload, str), f"Payload is not string: {payload}"
            assert len(payload) > 0, "Empty payload"
            assert '<' in payload, f"Payload missing opening bracket: {payload}"
            assert '>' in payload, f"Payload missing closing bracket: {payload}"

    def test_payload_variation_count(self, detector):
        """Test sufficient payload variations"""
        payload_count = len(detector.test_payloads)
        assert payload_count >= 10, f"Insufficient payloads: {payload_count}"
        assert payload_count <= 50, f"Too many payloads: {payload_count}"


class TestGETParameterInjection:
    """Test XSS injection via GET parameters"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_inject_payload_in_query_parameter(self, detector):
        """Test injecting payload in query string parameter"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>alert("xss")</script>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert result is not None
        assert isinstance(result, dict)
        assert 'status_code' in result

    @responses.activate
    def test_inject_multiple_query_parameters(self, detector):
        """Test injection with multiple query parameters"""
        endpoint = "https://api.example.com/api/filter"
        payloads = {
            'search': '<script>alert("xss")</script>',
            'filter': '<img src=x onerror="alert(\'xss\')">',
            'sort': 'name'
        }

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payloads},
            status=200,
            match_querystring=False
        )

        for param, payload in payloads.items():
            result = detector._test_payload(
                endpoint=endpoint,
                parameter_name=param,
                payload=payload,
                method='GET',
                headers=None,
                data=None
            )

            assert isinstance(result, dict)

    @responses.activate
    def test_inject_payload_with_url_encoding(self, detector):
        """Test payload injection with proper URL encoding"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>alert("xss")</script>'

        responses.add(
            responses.GET,
            endpoint,
            json={"query": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)
        assert 'payload' in result

    @responses.activate
    def test_inject_payload_with_special_characters(self, detector):
        """Test payload injection with special characters"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '"><script>alert(String.fromCharCode(88,83,83))</script>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_payload_with_query_string_separator(self, detector):
        """Test injection when endpoint already has query parameters"""
        endpoint = "https://api.example.com/api/search?existing=param"
        parameter = "q"
        payload = '<img src=x onerror="alert(\'xss\')">'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)


class TestPOSTParameterInjection:
    """Test XSS injection via POST request body"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_inject_payload_in_json_body(self, detector):
        """Test injecting payload in JSON POST body"""
        endpoint = "https://api.example.com/api/users"
        parameter = "name"
        payload = '<script>alert("xss")</script>'

        responses.add(
            responses.POST,
            endpoint,
            json={"user": {"name": payload}},
            status=200
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='POST',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_payload_in_nested_json_field(self, detector):
        """Test injection in nested JSON structure"""
        endpoint = "https://api.example.com/api/profile"
        parameter = "bio"
        payload = '<svg onload="alert(\'xss\')">'

        responses.add(
            responses.POST,
            endpoint,
            json={
                "profile": {
                    "user": {
                        "bio": payload
                    }
                }
            },
            status=200
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='POST',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_payload_with_authentication_headers(self, detector):
        """Test injection with authentication headers"""
        endpoint = "https://api.example.com/api/comments"
        parameter = "text"
        payload = '<img src=x onerror="alert(\'xss\')">'
        headers = {
            "Authorization": "Bearer token123",
            "Content-Type": "application/json"
        }

        responses.add(
            responses.POST,
            endpoint,
            json={"comment": payload},
            status=201
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='POST',
            headers=headers,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_payload_with_custom_headers(self, detector):
        """Test injection with custom headers"""
        endpoint = "https://api.example.com/api/data"
        parameter = "value"
        payload = '<body onload="alert(\'xss\')">'
        headers = {
            "X-Custom-Header": "custom-value",
            "X-API-Key": "secret-key"
        }

        responses.add(
            responses.POST,
            endpoint,
            json={"data": payload},
            status=200
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='POST',
            headers=headers,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_payload_in_multiple_json_fields(self, detector):
        """Test injection in multiple POST body fields"""
        endpoint = "https://api.example.com/api/users"
        
        payloads = {
            'name': '<script>alert("xss")</script>',
            'email': '<img src=x onerror="alert(\'xss\')">',
            'bio': '<svg onload="alert(\'xss\')">'
        }

        responses.add(
            responses.POST,
            endpoint,
            json={"user": payloads},
            status=200
        )

        for param, payload in payloads.items():
            result = detector._test_payload(
                endpoint=endpoint,
                parameter_name=param,
                payload=payload,
                method='POST',
                headers=None,
                data=None
            )

            assert isinstance(result, dict)


class TestPayloadVariations:
    """Test different payload variations and encoding"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_inject_case_insensitive_payload(self, detector):
        """Test payload with case variations"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<ScRiPt>alert("xss")</sCrIpT>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_html_entity_encoded_payload(self, detector):
        """Test HTML entity encoded payloads"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_url_encoded_payload(self, detector):
        """Test URL encoded payloads"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '%3Cscript%3Ealert(%22xss%22)%3C/script%3E'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_unicode_escape_sequence(self, detector):
        """Test Unicode escape sequences in payload"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>alert(String.fromCharCode(88,83,83))</script>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_payload_with_null_bytes(self, detector):
        """Test payloads with null byte injection"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>alert("xss")</script>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_polyglot_payload(self, detector):
        """Test polyglot payloads that work in multiple contexts"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '"><svg onload="alert(\'xss\')">'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)


class TestEventHandlerInjection:
    """Test injection via different event handlers"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_inject_onerror_event_handler(self, detector):
        """Test onerror event handler injection"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<img src=x onerror="alert(\'xss\')">'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_onload_event_handler(self, detector):
        """Test onload event handler injection"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<body onload="alert(\'xss\')">'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_onfocus_event_handler(self, detector):
        """Test onfocus event handler injection"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<input onfocus="alert(\'xss\')" autofocus>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_onstart_event_handler(self, detector):
        """Test onstart event handler injection"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<marquee onstart="alert(\'xss\')">'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_ontoggle_event_handler(self, detector):
        """Test ontoggle event handler injection"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<details open ontoggle="alert(\'xss\')">'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)


class TestCommentBypassTechniques:
    """Test bypass techniques using HTML comments"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_inject_payload_with_html_comment(self, detector):
        """Test payload injection with HTML comment bypass"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<!--<img src=x onerror="alert(\'xss\')">'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_multiline_comment_payload(self, detector):
        """Test multiline comment payload bypass"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '/*<img src=x onerror="alert(\'xss\')">'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)


class TestDOMandAttributeInjection:
    """Test DOM-based and attribute injection"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_inject_attribute_breakout(self, detector):
        """Test attribute breakout injection"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '" onload="alert(\'xss\')'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_tag_breakout(self, detector):
        """Test tag breakout injection"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '><script>alert("xss")</script><'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_protocol_handler(self, detector):
        """Test protocol handler injection"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<iframe src="javascript:alert(\'xss\')"></iframe>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)


class TestReflectionTypeDetection:
    """Test different reflection types"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_direct_reflection_detection(self, detector):
        """Test direct reflection in response"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>alert("xss")</script>'

        responses.add(
            responses.GET,
            endpoint,
            json={"query": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)
        assert 'reflection_found' in result or 'is_vulnerable' in result

    @responses.activate
    def test_html_encoded_reflection_detection(self, detector):
        """Test HTML-encoded reflection"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>alert("xss")</script>'
        encoded = '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'

        responses.add(
            responses.GET,
            endpoint,
            json={"result": encoded},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_partial_reflection_detection(self, detector):
        """Test partial payload reflection"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>alert("xss")</script>'
        partial = 'script alert'

        responses.add(
            responses.GET,
            endpoint,
            json={"result": partial},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)


class TestPayloadDeliveryMethods:
    """Test different payload delivery methods"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_inject_via_query_string(self, detector):
        """Test payload injection via query string"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>alert("xss")</script>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_via_request_body(self, detector):
        """Test payload injection via request body"""
        endpoint = "https://api.example.com/api/users"
        parameter = "name"
        payload = '<img src=x onerror="alert(\'xss\')">'

        responses.add(
            responses.POST,
            endpoint,
            json={"user": {"name": payload}},
            status=200
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='POST',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_via_custom_headers(self, detector):
        """Test payload injection via custom headers"""
        endpoint = "https://api.example.com/api/data"
        parameter = "X-Custom-Header"
        payload = '<script>alert("xss")</script>'
        headers = {parameter: payload}

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=headers,
            data=None
        )

        assert isinstance(result, dict)


class TestErrorMessageInjection:
    """Test payload injection in error messages"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_inject_in_404_error_message(self, detector):
        """Test injection in 404 error response"""
        endpoint = "https://api.example.com/api/users/invalid"
        parameter = "id"
        payload = '<img src=x onerror="alert(\'xss\')">'

        responses.add(
            responses.GET,
            endpoint,
            json={"error": f"User {payload} not found"},
            status=404,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_in_validation_error_message(self, detector):
        """Test injection in validation error"""
        endpoint = "https://api.example.com/api/users"
        parameter = "email"
        payload = '<script>alert("xss")</script>'

        responses.add(
            responses.POST,
            endpoint,
            json={"error": f"Invalid email: {payload}"},
            status=400
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='POST',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_in_exception_message(self, detector):
        """Test injection in exception/error message"""
        endpoint = "https://api.example.com/api/process"
        parameter = "data"
        payload = '<svg onload="alert(\'xss\')">'

        responses.add(
            responses.POST,
            endpoint,
            json={"error": f"Processing failed: {payload}"},
            status=500
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='POST',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)


class TestPerformanceAndEdgeCases:
    """Test performance and edge cases for payload injection"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_inject_with_very_long_payload(self, detector):
        """Test injection with very long payload"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>' + 'alert("xss");' * 1000 + '</script>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_with_null_bytes_bypass(self, detector):
        """Test injection with null byte bypass technique"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = '<script>\x00alert("xss")</script>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_with_very_long_parameter_name(self, detector):
        """Test injection with very long parameter name"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q" * 1000
        payload = '<script>alert("xss")</script>'

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)

    @responses.activate
    def test_inject_with_binary_null_payload(self, detector):
        """Test injection with binary null in payload"""
        endpoint = "https://api.example.com/api/search"
        parameter = "q"
        payload = b'<script>alert("xss")</script>\x00'.decode('utf-8', errors='ignore')

        responses.add(
            responses.GET,
            endpoint,
            json={"results": payload},
            status=200,
            match_querystring=False
        )

        result = detector._test_payload(
            endpoint=endpoint,
            parameter_name=parameter,
            payload=payload,
            method='GET',
            headers=None,
            data=None
        )

        assert isinstance(result, dict)


class TestIntegrationInjectionWorkflow:
    """Integration tests for complete injection workflows"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    @responses.activate
    def test_complete_get_injection_workflow(self, detector):
        """Test complete GET parameter injection workflow"""
        endpoint = "https://api.example.com/api/search"
        parameters = ["q", "filter", "sort"]

        for param in parameters:
            responses.add(
                responses.GET,
                endpoint,
                json={"results": '<script>alert("xss")</script>'},
                status=200,
                match_querystring=False
            )

            result = detector._test_payload(
                endpoint=endpoint,
                parameter_name=param,
                payload='<script>alert("xss")</script>',
                method='GET',
                headers=None,
                data=None
            )

            assert isinstance(result, dict)

    @responses.activate
    def test_complete_post_injection_workflow(self, detector):
        """Test complete POST parameter injection workflow"""
        endpoint = "https://api.example.com/api/users"
        parameters = ["name", "email", "bio"]

        for param in parameters:
            responses.add(
                responses.POST,
                endpoint,
                json={"user": {param: '<img src=x onerror="alert(\'xss\')">'}},
                status=201
            )

            result = detector._test_payload(
                endpoint=endpoint,
                parameter_name=param,
                payload='<img src=x onerror="alert(\'xss\')">',
                method='POST',
                headers=None,
                data=None
            )

            assert isinstance(result, dict)

    @responses.activate
    def test_mixed_get_post_injection_workflow(self, detector):
        """Test mixed GET and POST injection workflow"""
        get_endpoint = "https://api.example.com/api/search"
        post_endpoint = "https://api.example.com/api/users"

        # GET injection
        responses.add(
            responses.GET,
            get_endpoint,
            json={"results": '<script>alert("xss")</script>'},
            status=200,
            match_querystring=False
        )

        get_result = detector._test_payload(
            endpoint=get_endpoint,
            parameter_name='q',
            payload='<script>alert("xss")</script>',
            method='GET',
            headers=None,
            data=None
        )

        # POST injection
        responses.add(
            responses.POST,
            post_endpoint,
            json={"user": {"name": '<img src=x onerror="alert(\'xss\')">'}},
            status=201
        )

        post_result = detector._test_payload(
            endpoint=post_endpoint,
            parameter_name='name',
            payload='<img src=x onerror="alert(\'xss\')">',
            method='POST',
            headers=None,
            data=None
        )

        assert isinstance(get_result, dict)
        assert isinstance(post_result, dict)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
