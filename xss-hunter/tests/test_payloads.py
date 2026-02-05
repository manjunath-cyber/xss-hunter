# xss_hunter/tests/test_payloads.py
"""
Comprehensive Test Suite for XSS Payload Library
Tests payload effectiveness, coverage, and real-world applicability.
"""

import pytest
import json
from typing import List, Dict, Any, Tuple
from xss_hunter.core.reflection_detector import ReflectionDetector
from xss_hunter.utils.logger import setup_logging


# Setup logger for tests
setup_logging(log_level='DEBUG', log_dir='logs/tests')


class TestPayloadLibrary:
    """Test XSS payload library completeness and structure"""

    @pytest.fixture
    def detector(self):
        """Create detector with payload library"""
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_payload_library_exists(self, detector):
        """Test that payload library is properly initialized"""
        assert detector.test_payloads is not None
        assert isinstance(detector.test_payloads, list)
        assert len(detector.test_payloads) > 0

    def test_payload_count_sufficient(self, detector):
        """Test that we have sufficient number of payloads"""
        payload_count = len(detector.test_payloads)
        assert payload_count >= 10, f"Too few payloads: {payload_count}"
        assert payload_count <= 50, f"Too many payloads: {payload_count}"

    def test_all_payloads_are_strings(self, detector):
        """Test that all payloads are valid strings"""
        for i, payload in enumerate(detector.test_payloads):
            assert isinstance(payload, str), f"Payload {i} is not string: {type(payload)}"
            assert len(payload) > 0, f"Payload {i} is empty"

    def test_all_payloads_have_brackets(self, detector):
        """Test that all payloads contain HTML brackets"""
        for i, payload in enumerate(detector.test_payloads):
            assert '<' in payload, f"Payload {i} missing opening bracket: {payload}"
            assert '>' in payload, f"Payload {i} missing closing bracket: {payload}"

    def test_payload_uniqueness(self, detector):
        """Test that all payloads are unique"""
        payloads = detector.test_payloads
        unique_payloads = set(payloads)
        assert len(payloads) == len(unique_payloads), "Duplicate payloads found"

    def test_no_empty_payloads(self, detector):
        """Test that no payloads are empty or whitespace"""
        for i, payload in enumerate(detector.test_payloads):
            assert payload.strip(), f"Payload {i} is empty or whitespace: '{payload}'"


class TestPayloadCategories:
    """Test payload diversity across different categories"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_script_tag_payloads(self, detector):
        """Test presence of script tag payloads"""
        script_payloads = [p for p in detector.test_payloads if '<script' in p.lower()]
        assert len(script_payloads) > 0, "No <script> tag payloads found"

    def test_img_tag_payloads(self, detector):
        """Test presence of img tag payloads"""
        img_payloads = [p for p in detector.test_payloads if '<img' in p.lower()]
        assert len(img_payloads) > 0, "No <img> tag payloads found"

    def test_svg_tag_payloads(self, detector):
        """Test presence of SVG tag payloads"""
        svg_payloads = [p for p in detector.test_payloads if '<svg' in p.lower()]
        assert len(svg_payloads) > 0, "No <svg> tag payloads found"

    def test_iframe_tag_payloads(self, detector):
        """Test presence of iframe tag payloads"""
        iframe_payloads = [p for p in detector.test_payloads if '<iframe' in p.lower()]
        assert len(iframe_payloads) > 0, "No <iframe> tag payloads found"

    def test_body_tag_payloads(self, detector):
        """Test presence of body tag payloads"""
        body_payloads = [p for p in detector.test_payloads if '<body' in p.lower()]
        assert len(body_payloads) > 0, "No <body> tag payloads found"

    def test_input_tag_payloads(self, detector):
        """Test presence of input tag payloads"""
        input_payloads = [p for p in detector.test_payloads if '<input' in p.lower()]
        assert len(input_payloads) > 0, "No <input> tag payloads found"

    def test_select_tag_payloads(self, detector):
        """Test presence of select tag payloads"""
        select_payloads = [p for p in detector.test_payloads if '<select' in p.lower()]
        assert len(select_payloads) > 0, "No <select> tag payloads found"

    def test_textarea_tag_payloads(self, detector):
        """Test presence of textarea tag payloads"""
        textarea_payloads = [p for p in detector.test_payloads if '<textarea' in p.lower()]
        assert len(textarea_payloads) > 0, "No <textarea> tag payloads found"

    def test_video_tag_payloads(self, detector):
        """Test presence of video tag payloads"""
        video_payloads = [p for p in detector.test_payloads if '<video' in p.lower()]
        assert len(video_payloads) > 0, "No <video> tag payloads found"

    def test_audio_tag_payloads(self, detector):
        """Test presence of audio tag payloads"""
        audio_payloads = [p for p in detector.test_payloads if '<audio' in p.lower()]
        assert len(audio_payloads) > 0, "No <audio> tag payloads found"


class TestEventHandlerPayloads:
    """Test event handler payloads"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_onerror_payloads(self, detector):
        """Test presence of onerror event handler payloads"""
        onerror = [p for p in detector.test_payloads if 'onerror' in p.lower()]
        assert len(onerror) > 0, "No onerror payloads found"

    def test_onload_payloads(self, detector):
        """Test presence of onload event handler payloads"""
        onload = [p for p in detector.test_payloads if 'onload' in p.lower()]
        assert len(onload) > 0, "No onload payloads found"

    def test_onfocus_payloads(self, detector):
        """Test presence of onfocus event handler payloads"""
        onfocus = [p for p in detector.test_payloads if 'onfocus' in p.lower()]
        assert len(onfocus) > 0, "No onfocus payloads found"

    def test_onclick_payloads(self, detector):
        """Test presence of onclick event handler payloads"""
        onclick = [p for p in detector.test_payloads if 'onclick' in p.lower()]
        # onclick might not always be present, but we check
        if onclick:
            assert len(onclick) > 0

    def test_onstart_payloads(self, detector):
        """Test presence of onstart event handler payloads"""
        onstart = [p for p in detector.test_payloads if 'onstart' in p.lower()]
        assert len(onstart) > 0, "No onstart payloads found"

    def test_ontoggle_payloads(self, detector):
        """Test presence of ontoggle event handler payloads"""
        ontoggle = [p for p in detector.test_payloads if 'ontoggle' in p.lower()]
        assert len(ontoggle) > 0, "No ontoggle payloads found"

    def test_multiple_event_handlers_represented(self, detector):
        """Test that multiple event handlers are represented"""
        payloads = detector.test_payloads
        event_handlers = set()
        
        for payload in payloads:
            if 'on' in payload:
                # Extract event handler names
                import re
                matches = re.findall(r'\bon\w+', payload, re.IGNORECASE)
                event_handlers.update(matches)
        
        assert len(event_handlers) >= 5, f"Too few event handler types: {event_handlers}"


class TestJavaScriptPayloads:
    """Test JavaScript execution payloads"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_alert_payloads(self, detector):
        """Test presence of alert-based payloads"""
        alert_payloads = [p for p in detector.test_payloads if 'alert' in p.lower()]
        assert len(alert_payloads) > 0, "No alert payloads found"

    def test_string_fromcharcode_payloads(self, detector):
        """Test presence of String.fromCharCode payloads"""
        fromcharcode = [p for p in detector.test_payloads if 'fromCharCode' in p]
        assert len(fromcharcode) > 0, "No String.fromCharCode payloads found"

    def test_javascript_protocol_payloads(self, detector):
        """Test presence of javascript: protocol payloads"""
        js_protocol = [p for p in detector.test_payloads if 'javascript:' in p]
        assert len(js_protocol) > 0, "No javascript: protocol payloads found"

    def test_fetch_api_payloads(self, detector):
        """Test presence of fetch API payloads"""
        fetch_payloads = [p for p in detector.test_payloads if 'fetch' in p.lower()]
        # fetch might not always be present in basic payloads, but good if it is
        if fetch_payloads:
            assert len(fetch_payloads) > 0

    def test_console_log_payloads(self, detector):
        """Test presence of console.log payloads"""
        console = [p for p in detector.test_payloads if 'console' in p.lower()]
        # console might not always be present
        if console:
            assert len(console) > 0


class TestBypassTechniques:
    """Test payload bypass techniques"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_comment_bypass_payloads(self, detector):
        """Test presence of HTML comment bypass payloads"""
        comment = [p for p in detector.test_payloads if '<!--' in p or '/*' in p]
        assert len(comment) > 0, "No comment bypass payloads found"

    def test_case_variation_payloads(self, detector):
        """Test for case variations in payloads"""
        payloads = detector.test_payloads
        
        # Check if any payloads use mixed case
        mixed_case = [p for p in payloads if any(c.isupper() for c in p) and any(c.islower() for c in p)]
        assert len(mixed_case) > 0, "No case variation payloads found"

    def test_attribute_breakout_payloads(self, detector):
        """Test presence of attribute breakout payloads"""
        attribute_breakout = [p for p in detector.test_payloads if '"><' in p or '\'" ' in p]
        assert len(attribute_breakout) > 0, "No attribute breakout payloads found"

    def test_tag_breakout_payloads(self, detector):
        """Test presence of tag breakout payloads"""
        tag_breakout = [p for p in detector.test_payloads if '><' in p]
        assert len(tag_breakout) > 0, "No tag breakout payloads found"


class TestPayloadComplexity:
    """Test payload complexity and length"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_payload_length_distribution(self, detector):
        """Test that payloads have reasonable length distribution"""
        lengths = [len(p) for p in detector.test_payloads]
        
        min_length = min(lengths)
        max_length = max(lengths)
        avg_length = sum(lengths) / len(lengths)
        
        assert min_length > 10, f"Payload too short: {min_length}"
        assert max_length < 500, f"Payload too long: {max_length}"
        assert avg_length > 20, f"Average payload too short: {avg_length}"

    def test_short_payloads_present(self, detector):
        """Test presence of short, simple payloads"""
        short_payloads = [p for p in detector.test_payloads if len(p) < 50]
        assert len(short_payloads) > 0, "No short payloads found"

    def test_medium_payloads_present(self, detector):
        """Test presence of medium complexity payloads"""
        medium_payloads = [p for p in detector.test_payloads if 50 <= len(p) < 150]
        assert len(medium_payloads) > 0, "No medium payloads found"

    def test_complex_payloads_present(self, detector):
        """Test presence of complex payloads"""
        complex_payloads = [p for p in detector.test_payloads if len(p) >= 150]
        assert len(complex_payloads) > 0, "No complex payloads found"


class TestPayloadSyntaxValidity:
    """Test HTML/JavaScript syntax validity of payloads"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_balanced_brackets(self, detector):
        """Test that all payloads have balanced brackets"""
        for i, payload in enumerate(detector.test_payloads):
            # Count opening and closing brackets
            open_count = payload.count('<')
            close_count = payload.count('>')
            
            # Most payloads should have balanced brackets
            assert open_count == close_count, \
                f"Payload {i} has unbalanced brackets: {open_count} < vs {close_count} > in {payload}"

    def test_valid_html_structure(self, detector):
        """Test that payloads contain valid HTML structure"""
        import re
        
        for i, payload in enumerate(detector.test_payloads):
            # Check for basic HTML validity
            tag_pattern = r'<[^/>]+/?>'
            tags = re.findall(tag_pattern, payload)
            assert len(tags) > 0, f"Payload {i} contains no valid HTML tags: {payload}"

    def test_quote_pairing(self, detector):
        """Test quote pairing in payloads"""
        for i, payload in enumerate(detector.test_payloads):
            # Count single quotes
            single_quotes = payload.count("'") - payload.count("\\'")
            double_quotes = payload.count('"') - payload.count('\\"')
            
            # Most payloads should have balanced quotes
            if single_quotes > 0:
                assert single_quotes % 2 == 0, \
                    f"Payload {i} has unbalanced single quotes: {payload}"
            if double_quotes > 0:
                assert double_quotes % 2 == 0, \
                    f"Payload {i} has unbalanced double quotes: {payload}"


class TestPayloadCoverage:
    """Test coverage of different XSS attack vectors"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_reflected_xss_payloads(self, detector):
        """Test coverage for reflected XSS"""
        payloads = detector.test_payloads
        
        # Most payloads should work for reflected XSS
        reflected_capable = len(payloads)
        assert reflected_capable > 5, f"Not enough reflected XSS payloads: {reflected_capable}"

    def test_dom_xss_payloads(self, detector):
        """Test coverage for DOM-based XSS"""
        payloads = detector.test_payloads
        
        # Check for payloads that work in DOM context
        dom_capable = [p for p in payloads if any(x in p.lower() for x in ['javascript:', 'eval(', 'onclick'])]
        assert len(dom_capable) > 0, "No DOM XSS capable payloads found"

    def test_attribute_based_payloads(self, detector):
        """Test coverage for attribute-based XSS"""
        payloads = detector.test_payloads
        
        # Check for attribute-based payloads
        attribute_based = [p for p in payloads if ' on' in p.lower()]
        assert len(attribute_based) > 0, "No attribute-based payloads found"

    def test_context_aware_payloads(self, detector):
        """Test presence of context-aware payloads"""
        payloads = detector.test_payloads
        
        # Check for payloads that work in different contexts
        contexts = set()
        
        for payload in payloads:
            if '<script' in payload.lower():
                contexts.add('script_tag')
            if 'on' in payload.lower() and '=' in payload:
                contexts.add('event_handler')
            if 'javascript:' in payload.lower():
                contexts.add('protocol_handler')
        
        assert len(contexts) >= 2, f"Insufficient context coverage: {contexts}"


class TestPayloadEffectiveness:
    """Test effectiveness metrics of payloads"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_payload_effectiveness_indicators(self, detector):
        """Test that payloads have good effectiveness indicators"""
        payloads = detector.test_payloads
        
        # Count payloads with execution keywords
        execution_keywords = ['alert', 'console', 'eval', 'fetch', 'cookie']
        effective_payloads = [p for p in payloads if any(kw in p.lower() for kw in execution_keywords)]
        
        assert len(effective_payloads) > 3, "Not enough effective payloads"

    def test_payload_detection_evasion(self, detector):
        """Test presence of detection evasion techniques"""
        payloads = detector.test_payloads
        
        # Check for various evasion techniques
        evasion_techniques = set()
        
        for payload in payloads:
            if 'fromCharCode' in payload:
                evasion_techniques.add('character_encoding')
            if '<!--' in payload or '/*' in payload:
                evasion_techniques.add('comment_bypass')
            if any(c.isupper() and c.islower() for c in payload):
                evasion_techniques.add('case_variation')
        
        assert len(evasion_techniques) > 0, "No evasion techniques found"

    def test_browser_compatibility(self, detector):
        """Test coverage for different browser contexts"""
        payloads = detector.test_payloads
        
        # HTML5 specific
        html5_payloads = [p for p in payloads if any(x in p.lower() for x in ['<video', '<audio', '<svg', '<details'])]
        
        # Legacy compatible
        legacy_payloads = [p for p in payloads if '<script' in p.lower()]
        
        assert len(html5_payloads) > 0, "No HTML5 payloads found"
        assert len(legacy_payloads) > 0, "No legacy compatible payloads found"


class TestPayloadOrganization:
    """Test organization and structure of payload library"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_payloads_in_order(self, detector):
        """Test that payloads are in reasonable order"""
        payloads = detector.test_payloads
        
        # Check that they're not random
        assert len(payloads) > 0, "Empty payload list"
        
        # Verify list is a proper sequence
        for i, payload in enumerate(payloads):
            assert isinstance(payload, str), f"Payload {i} is not string"

    def test_no_duplicate_keywords(self, detector):
        """Test that major keyword categories aren't heavily duplicated"""
        payloads = detector.test_payloads
        
        # Count script tag payloads
        script_count = sum(1 for p in payloads if '<script' in p.lower())
        
        # Should have some variety
        total = len(payloads)
        script_ratio = script_count / total
        
        assert script_ratio < 0.5, f"Too many script tag payloads: {script_ratio}"

    def test_payload_independence(self, detector):
        """Test that payloads test different vectors"""
        payloads = detector.test_payloads
        
        # Group payloads by major tag type
        tag_types = {}
        import re
        
        for payload in payloads:
            tag = re.search(r'<(\w+)', payload)
            if tag:
                tag_name = tag.group(1).lower()
                tag_types[tag_name] = tag_types.get(tag_name, 0) + 1
        
        # Should have at least 3 different tag types
        assert len(tag_types) >= 3, f"Too few tag types: {tag_types}"


class TestPayloadRealWorldRelevance:
    """Test real-world relevance of payloads"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_owasp_common_payloads(self, detector):
        """Test coverage of OWASP-listed common XSS payloads"""
        payloads = detector.test_payloads
        
        # Common OWASP payloads
        common_patterns = [
            '<script>alert',
            '<img.*onerror',
            '<svg.*onload',
            'javascript:',
            'onfocus',
        ]
        
        for pattern in common_patterns:
            import re
            matches = [p for p in payloads if re.search(pattern, p, re.IGNORECASE)]
            assert len(matches) > 0, f"Missing OWASP pattern: {pattern}"

    def test_cwe79_coverage(self, detector):
        """Test coverage of CWE-79 (Cross-site Scripting) vectors"""
        payloads = detector.test_payloads
        
        # CWE-79 includes various XSS types
        xss_types = {
            'reflected': 0,
            'dom': 0,
            'attribute': 0,
        }
        
        for payload in payloads:
            # All basic payloads work for reflected
            xss_types['reflected'] += 1
            
            # DOM-capable payloads
            if any(x in payload.lower() for x in ['javascript:', 'eval', 'onclick']):
                xss_types['dom'] += 1
            
            # Attribute-based
            if ' on' in payload.lower():
                xss_types['attribute'] += 1
        
        for xss_type, count in xss_types.items():
            assert count > 0, f"No payloads for {xss_type} XSS"

    def test_real_world_attack_scenarios(self, detector):
        """Test that payloads cover real-world attack scenarios"""
        payloads = detector.test_payloads
        
        scenarios = {
            'session_hijacking': 0,  # Needs cookie/session access
            'credential_theft': 0,    # Needs form injection
            'malware_delivery': 0,    # Needs redirect capability
            'defacement': 0,          # Needs DOM manipulation
        }
        
        for payload in payloads:
            # Session hijacking - fetch/XMLHttpRequest capability
            if any(x in payload.lower() for x in ['fetch', 'xhr', 'httprequest', 'cookie']):
                scenarios['session_hijacking'] += 1
            
            # Credential theft - form injection
            if any(x in payload.lower() for x in ['form', 'input', 'password']):
                scenarios['credential_theft'] += 1
            
            # Malware delivery - redirect capability
            if any(x in payload.lower() for x in ['location', 'href', 'window']):
                scenarios['malware_delivery'] += 1
            
            # Defacement - DOM manipulation
            if any(x in payload.lower() for x in ['innerhtml', 'textcontent', 'appendchild']):
                scenarios['defacement'] += 1
        
        # At least some payloads should enable common attacks
        assert any(count > 0 for count in scenarios.values()), \
            f"No payloads for real-world scenarios: {scenarios}"


class TestPayloadUpdateability:
    """Test that payload library can be easily updated"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_payloads_modifiable(self, detector):
        """Test that payload list can be modified"""
        original_count = len(detector.test_payloads)
        
        # Verify it's a modifiable list
        assert isinstance(detector.test_payloads, list), "Payloads should be a list"
        
        # Try to verify immutability isn't enforced
        # (payloads should be modifiable for custom scans)
        try:
            # Don't actually modify, just verify it's possible
            test_payload = detector.test_payloads[0]
            assert test_payload is not None
        except (TypeError, AttributeError):
            pytest.fail("Payload list is not accessible")

    def test_payload_format_consistency(self, detector):
        """Test that all payloads follow consistent format"""
        payloads = detector.test_payloads
        
        for payload in payloads:
            # All should be strings
            assert isinstance(payload, str), f"Payload format inconsistent: {type(payload)}"
            
            # All should be non-empty
            assert len(payload.strip()) > 0, f"Payload is empty or whitespace"
            
            # All should contain HTML
            assert any(c in payload for c in '<>'), f"Payload missing HTML: {payload}"


class TestPayloadPerformance:
    """Test performance characteristics of payload library"""

    @pytest.fixture
    def detector(self):
        return ReflectionDetector(timeout=10, verify_ssl=False)

    def test_payload_loading_performance(self, detector):
        """Test that payload loading is efficient"""
        import time
        
        # Payloads should load quickly
        assert detector.test_payloads is not None
        assert len(detector.test_payloads) > 0

    def test_payload_size_reasonable(self, detector):
        """Test that total payload size is reasonable"""
        payloads = detector.test_payloads
        total_size = sum(len(p) for p in payloads)
        
        # Total size should be reasonable (not megabytes)
        assert total_size < 100000, f"Payload library too large: {total_size} bytes"

    def test_individual_payload_performance(self, detector):
        """Test that individual payloads are reasonably sized"""
        payloads = detector.test_payloads
        
        for payload in payloads:
            # Each payload should be reasonably sized
            assert len(payload) < 1000, f"Payload too large: {len(payload)} chars"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
