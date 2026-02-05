# core/reflection_detector.py
"""
Reflection Detector Module
Detects if payloads are reflected in responses
"""

from xss_hunter.utils.validators import ResponseValidator
from xss_hunter.utils.logger import get_logger

logger = get_logger('core.reflection_detector')


class ReflectionDetector:
    """Detects payload reflection in responses"""

    def is_reflected(self, payload: str, response_body: str) -> bool:
        """
        Check if payload is reflected in response.
        
        Args:
            payload: Original payload
            response_body: Response body
        
        Returns:
            True if reflected
        """
        result = ResponseValidator.check_reflection(payload, response_body)
        return result.valid

    def get_reflection_type(self, payload: str, response_body: str) -> str:
        """
        Get type of reflection.
        
        Args:
            payload: Original payload
            response_body: Response body
        
        Returns:
            Reflection type (direct, html_encoded, url_encoded, partial)
        """
        result = ResponseValidator.check_reflection(payload, response_body)
        if not result.valid:
            return 'none'

        reflection_types = result.details.get('reflection_types', {})
        for reflection_type, is_reflected in reflection_types.items():
            if is_reflected:
                return reflection_type

        return 'none'
