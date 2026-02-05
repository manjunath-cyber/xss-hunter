import pytest
from xss_hunter.utils.validators import (
    URLValidator, PayloadValidator, ResponseValidator, ParameterValidator,
    HTTPStatusValidator, RequestValidator, ValidationResult, PayloadType
)

class TestURLValidator:
    def test_validate_url_valid(self):
        valid_urls = [
            "https://example.com",
            "http://localhost:8080",
            "https://sub.domain.co.uk/path?q=1",
            "http://192.168.1.1"
        ]
        for url in valid_urls:
            result = URLValidator.validate_url(url)
            assert result.valid, f"Failed for {url}"
            assert result.details['scheme'] in ['http', 'https']

    def test_validate_url_invalid(self):
        invalid_urls = [
            "ftp://example.com",
            "example.com",
            "http:/example.com",
            "",
            None
        ]
        for url in invalid_urls:
            result = URLValidator.validate_url(url)
            assert not result.valid, f"Should fail for {url}"

    def test_normalize_url(self):
        assert URLValidator.normalize_url("example.com") == "https://example.com"
        assert URLValidator.normalize_url("http://example.com/") == "http://example.com"

class TestPayloadValidator:
    def test_validate_payload_valid(self):
        valid_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<a href=javascript:alert(1)>click</a>"
        ]
        for payload in valid_payloads:
            result = PayloadValidator.validate_payload(payload)
            assert result.valid, f"Failed for {payload}"
            assert result.details['type'] != PayloadType.UNKNOWN

    def test_validate_payload_invalid(self):
        invalid_payloads = [
            "just text",
            123,
            "<script"
        ]
        for payload in invalid_payloads:
            result = PayloadValidator.validate_payload(payload)
            assert not result.valid, f"Should fail for {payload}"

    def test_is_effective_payload(self):
        assert PayloadValidator.is_effective_payload("<script>alert(1)</script>")
        assert PayloadValidator.is_effective_payload("<img src=x onerror=console.log(1)>")
        assert not PayloadValidator.is_effective_payload("<div>hello</div>")

class TestResponseValidator:
    def test_validate_json_response(self):
        assert ResponseValidator.validate_json_response('{"key": "value"}').valid
        assert not ResponseValidator.validate_json_response('{invalid}').valid

    def test_check_reflection_direct(self):
        payload = "<script>alert(1)</script>"
        response = "<html><body>" + payload + "</body></html>"
        result = ResponseValidator.check_reflection(payload, response)
        assert result.valid
        assert result.details['reflected']
        assert result.details['reflection_types']['direct']

    def test_check_reflection_encoded(self):
        payload = "<script>alert(1)</script>"
        # Simple simulation of HTML encoding
        response = "<html><body>&lt;script&gt;alert(1)&lt;/script&gt;</body></html>"
        result = ResponseValidator.check_reflection(payload, response)
        assert result.valid
        assert result.details['reflection_types']['html_encoded']

class TestParameterValidator:
    def test_validate_parameter_name(self):
        assert ParameterValidator.validate_parameter_name("valid_param").valid
        assert not ParameterValidator.validate_parameter_name("invalid param").valid
        assert not ParameterValidator.validate_parameter_name("").valid

    def test_extract_parameters(self):
        url = "https://example.com?q=test&id=123"
        result = ParameterValidator.extract_parameters_from_url(url)
        assert result.valid
        assert result.details['parameters']['q'] == 'test'
        assert result.details['parameters']['id'] == '123'

class TestHTTPStatusValidator:
    def test_validate_status_code(self):
        assert HTTPStatusValidator.validate_status_code(200).valid
        assert HTTPStatusValidator.validate_status_code(404).valid
        assert HTTPStatusValidator.validate_status_code(500).valid
        assert not HTTPStatusValidator.validate_status_code(999).valid

    def test_categories(self):
        assert HTTPStatusValidator.get_status_category(200) == 'success'
        assert HTTPStatusValidator.get_status_category(404) == 'client_error'

class TestRequestValidator:
    def test_validate_method(self):
        assert RequestValidator.validate_method("GET").valid
        assert RequestValidator.validate_method("post").valid
        assert not RequestValidator.validate_method("INVALID").valid

    def test_validate_headers(self):
        headers = {"Content-Type": "application/json", "X-Custom": "value"}
        assert RequestValidator.validate_headers(headers).valid
        assert not RequestValidator.validate_headers({"Invalid Header": "value"}).valid
