# xss_hunter/core/reflection_detector.py
"""
Reflection Detector Module
Detects reflected XSS vulnerabilities by injecting payloads and checking for reflection in API responses.
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode, parse_qs, urlparse
import requests
from requests.models import Response


from utils.logger import log_info, log_error, get_logger

class ReflectionDetector:
    """
    Detects reflected XSS vulnerabilities in API endpoints.
    Tests if user input is directly reflected in the API response without proper sanitization.
    """

    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        """
        Initialize the Reflection Detector.
        
        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.logger = get_logger('xss_hunter.core.reflection_detector')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.test_payloads = [
            '<script>alert("xss")</script>',
            '<img src=x onerror="alert(\'xss\')">',
            '<svg onload="alert(\'xss\')">',
            '"><script>alert(String.fromCharCode(88,83,83))</script>',
            '<iframe src="javascript:alert(\'xss\')"></iframe>',
            '<body onload="alert(\'xss\')">',
            '<input onfocus="alert(\'xss\')" autofocus>',
            '<select onfocus="alert(\'xss\')" autofocus>',
            '<textarea onfocus="alert(\'xss\')" autofocus>',
            '<keygen onfocus="alert(\'xss\')" autofocus>',
            '<video><source onerror="alert(\'xss\')">',
            '<audio src=x onerror="alert(\'xss\')">',
            '<!--<img src=x onerror="alert(\'xss\')">-->',
            '<details open ontoggle="alert(\'xss\')">',
            '<marquee onstart="alert(\'xss\')">',
        ]

    def detect_reflected_xss(
        self,
        endpoint: str,
        parameter_name: str,
        method: str = 'GET',
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Detect reflected XSS in a specific API parameter.
        
        Args:
            endpoint: Full API endpoint URL
            parameter_name: Name of the parameter to test
            method: HTTP method (GET, POST, etc.)
            headers: Additional headers to send
            data: Request body data (for POST requests)
        
        Returns:
            Dictionary with detection results
        """
        self.logger.info(f"Starting XSS detection for {endpoint}")
        vulnerabilities = []
        
        for payload in self.test_payloads:
            try:
                result = self._test_payload(
                    endpoint=endpoint,
                    parameter_name=parameter_name,
                    payload=payload,
                    method=method,
                    headers=headers,
                    data=data
                )
                
                if result['is_vulnerable']:
                    self.logger.warning(
                        f"XSS vulnerability found",
                        endpoint=endpoint,
                        parameter=parameter_name,
                        payload=payload
                    )
                    vulnerabilities.append(result)
            except Exception as e:
                self.logger.error(f"Error testing payload: {str(e)}")
        
        return {
            'endpoint': endpoint,
            'parameter': parameter_name,
            'method': method,
            'vulnerable': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities,
            'total_payloads_tested': len(self.test_payloads),
            'successful_payloads': len(vulnerabilities)
        }

    def _test_payload(
        self,
        endpoint: str,
        parameter_name: str,
        payload: str,
        method: str,
        headers: Optional[Dict[str, str]],
        data: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Test a single payload against the endpoint.
        
        Args:
            endpoint: API endpoint URL
            parameter_name: Parameter to inject payload into
            payload: XSS payload to test
            method: HTTP method
            headers: Request headers
            data: Request body
        
        Returns:
            Dictionary with test result details
        """
        try:
            test_headers = headers or {}
            test_data = data or {}
            
            # Prepare the request based on method
            if method.upper() == 'GET':
                # Add payload to URL parameters
                separator = '&' if '?' in endpoint else '?'
                test_url = f"{endpoint}{separator}{urlencode({parameter_name: payload})}"
                response = requests.get(
                    test_url,
                    headers=test_headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            
            elif method.upper() == 'POST':
                # Add payload to POST data
                test_data[parameter_name] = payload
                response = requests.post(
                    endpoint,
                    headers=test_headers,
                    json=test_data,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            
            else:
                return self._create_error_result(endpoint, parameter_name, payload, 'Unsupported HTTP method')
            
            # Check if payload is reflected in response
            is_reflected = self._check_reflection(payload, response)
            
            return {
                'payload': payload,
                'is_vulnerable': is_reflected,
                'status_code': response.status_code,
                'response_length': len(response.text),
                'reflection_found': is_reflected,
                'confidence': 'high' if is_reflected else 'none'
            }
        
        except requests.exceptions.Timeout:
            return self._create_error_result(endpoint, parameter_name, payload, 'Request timeout')
        except requests.exceptions.ConnectionError:
            return self._create_error_result(endpoint, parameter_name, payload, 'Connection error')
        except Exception as e:
            return self._create_error_result(endpoint, parameter_name, payload, str(e))

    def _check_reflection(self, payload: str, response: Response) -> bool:
        """
        Check if the payload is reflected in the response.
        
        Args:
            payload: Original payload sent
            response: Response object from the request
        
        Returns:
            True if payload is found in response, False otherwise
        """
        response_text = response.text.lower()
        payload_lower = payload.lower()
        
        # Direct reflection check
        if payload_lower in response_text:
            return True
        
        # Check for HTML-encoded reflection
        html_encoded = self._html_encode(payload)
        if html_encoded.lower() in response_text:
            return True
        
        # Check for URL-encoded reflection
        url_encoded = self._url_encode(payload)
        if url_encoded.lower() in response_text:
            return True
        
        return False

    @staticmethod
    def _html_encode(text: str) -> str:
        """HTML encode special characters."""
        return (
            text.replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#x27;')
        )

    @staticmethod
    def _url_encode(text: str) -> str:
        """URL encode the text."""
        return urlencode({'': text}).split('=')[1] if '=' in urlencode({'': text}) else ''

    @staticmethod
    def _create_error_result(endpoint: str, parameter: str, payload: str, error: str) -> Dict[str, Any]:
        """Create an error result dictionary."""
        return {
            'payload': payload,
            'is_vulnerable': False,
            'status_code': None,
            'response_length': 0,
            'error': error,
            'confidence': 'none'
        }

    def scan_multiple_parameters(
        self,
        endpoint: str,
        parameters: List[str],
        method: str = 'GET',
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Scan multiple parameters in a single API endpoint.
        
        Args:
            endpoint: API endpoint URL
            parameters: List of parameter names to test
            method: HTTP method
            headers: Request headers
            data: Request body data
        
        Returns:
            Dictionary with results for all parameters
        """
        results = {
            'endpoint': endpoint,
            'method': method,
            'total_parameters': len(parameters),
            'vulnerable_parameters': [],
            'parameter_results': []
        }
        
        for param in parameters:
            result = self.detect_reflected_xss(
                endpoint=endpoint,
                parameter_name=param,
                method=method,
                headers=headers,
                data=data
            )
            
            results['parameter_results'].append(result)
            
            if result['vulnerable']:
                results['vulnerable_parameters'].append({
                    'parameter': param,
                    'vulnerability_count': len(result['vulnerabilities'])
                })
        
        results['total_vulnerable'] = len(results['vulnerable_parameters'])
        
        return results