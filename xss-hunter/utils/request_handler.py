# xss_hunter/utils/request_handler.py
"""
Request Handler Module for XSS Hunter
Provides centralized HTTP request management with retry logic, timeout handling, and security features.
"""

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from typing import Optional, Dict, Any, Tuple, List
from urllib.parse import urlencode, parse_qs, urlparse, quote
from dataclasses import dataclass
from enum import Enum
import time
import json
from xss_hunter.utils.logger import get_logger

logger = get_logger('xss_hunter.utils.request_handler')


class HTTPMethod(Enum):
    """HTTP Methods supported by request handler"""
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    DELETE = 'DELETE'
    PATCH = 'PATCH'
    HEAD = 'HEAD'
    OPTIONS = 'OPTIONS'


@dataclass
class RequestConfig:
    """Configuration for HTTP requests"""
    timeout: int = 10
    verify_ssl: bool = True
    allow_redirects: bool = True
    max_redirects: int = 5
    retry_count: int = 3
    backoff_factor: float = 0.5
    user_agent: str = 'XSS-Hunter/1.0.0 (Security Scanner)'
    follow_redirects: bool = True
    raise_on_error: bool = False


@dataclass
class RequestResult:
    """Result of HTTP request"""
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time_ms: float
    request_url: str
    request_method: str
    success: bool
    error: Optional[str] = None
    redirected: bool = False
    final_url: Optional[str] = None


class RequestHandler:
    """
    Centralized HTTP request handler for XSS Hunter.
    Handles retries, timeouts, SSL verification, and security features.
    """

    def __init__(self, config: Optional[RequestConfig] = None):
        """
        Initialize Request Handler.
        
        Args:
            config: RequestConfig instance with custom settings
        """
        self.config = config or RequestConfig()
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """
        Create requests session with retry strategy.
        
        Returns:
            Configured requests.Session
        """
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.retry_count,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=['GET', 'POST', 'PUT', 'DELETE'],
            backoff_factor=self.config.backoff_factor
        )

        # Mount adapters
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        # Set default headers
        session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': 'application/json, text/html, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })

        return session

    def get(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> RequestResult:
        """
        Send GET request.
        
        Args:
            url: Request URL
            params: Query parameters
            headers: Custom headers
            **kwargs: Additional arguments
        
        Returns:
            RequestResult object
        """
        return self._request(
            method=HTTPMethod.GET,
            url=url,
            params=params,
            headers=headers,
            **kwargs
        )

    def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> RequestResult:
        """
        Send POST request.
        
        Args:
            url: Request URL
            data: Form data
            json_data: JSON data
            headers: Custom headers
            **kwargs: Additional arguments
        
        Returns:
            RequestResult object
        """
        return self._request(
            method=HTTPMethod.POST,
            url=url,
            data=data,
            json_data=json_data,
            headers=headers,
            **kwargs
        )

    def put(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> RequestResult:
        """
        Send PUT request.
        
        Args:
            url: Request URL
            data: Form data
            json_data: JSON data
            headers: Custom headers
            **kwargs: Additional arguments
        
        Returns:
            RequestResult object
        """
        return self._request(
            method=HTTPMethod.PUT,
            url=url,
            data=data,
            json_data=json_data,
            headers=headers,
            **kwargs
        )

    def delete(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> RequestResult:
        """
        Send DELETE request.
        
        Args:
            url: Request URL
            headers: Custom headers
            **kwargs: Additional arguments
        
        Returns:
            RequestResult object
        """
        return self._request(
            method=HTTPMethod.DELETE,
            url=url,
            headers=headers,
            **kwargs
        )

    def _request(
        self,
        method: HTTPMethod,
        url: str,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> RequestResult:
        """
        Internal request method.
        
        Args:
            method: HTTP method
            url: Request URL
            params: Query parameters
            data: Form data
            json_data: JSON data
            headers: Custom headers
            **kwargs: Additional arguments
        
        Returns:
            RequestResult object
        """
        start_time = time.time()
        request_headers = self._prepare_headers(headers)

        try:
            # Log request
            logger.debug(
                f"Making {method.value} request",
                method=method.value,
                url=url,
                params=params
            )

            # Make request
            if method == HTTPMethod.GET:
                response = self.session.get(
                    url,
                    params=params,
                    headers=request_headers,
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl,
                    allow_redirects=self.config.allow_redirects,
                    **kwargs
                )
            
            elif method == HTTPMethod.POST:
                response = self.session.post(
                    url,
                    data=data,
                    json=json_data,
                    headers=request_headers,
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl,
                    allow_redirects=self.config.allow_redirects,
                    **kwargs
                )
            
            elif method == HTTPMethod.PUT:
                response = self.session.put(
                    url,
                    data=data,
                    json=json_data,
                    headers=request_headers,
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl,
                    allow_redirects=self.config.allow_redirects,
                    **kwargs
                )
            
            elif method == HTTPMethod.DELETE:
                response = self.session.delete(
                    url,
                    headers=request_headers,
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl,
                    allow_redirects=self.config.allow_redirects,
                    **kwargs
                )
            
            else:
                raise ValueError(f"Unsupported method: {method}")

            # Calculate response time
            response_time_ms = (time.time() - start_time) * 1000

            # Log successful response
            logger.debug(
                f"Request successful",
                method=method.value,
                url=url,
                status_code=response.status_code,
                response_time_ms=response_time_ms
            )

            # Create result
            result = RequestResult(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
                response_time_ms=response_time_ms,
                request_url=url,
                request_method=method.value,
                success=200 <= response.status_code < 300,
                redirected=response.url != url,
                final_url=response.url
            )

            return result

        except requests.exceptions.Timeout:
            response_time_ms = (time.time() - start_time) * 1000
            logger.error(
                f"Request timeout",
                method=method.value,
                url=url,
                timeout=self.config.timeout,
                response_time=response_time_ms
            )
            return self._create_error_result(
                method=method,
                url=url,
                response_time_ms=response_time_ms,
                error=f"Request timeout after {self.config.timeout}s"
            )

        except requests.exceptions.ConnectionError:
            response_time_ms = (time.time() - start_time) * 1000
            logger.error(
                f"Connection error",
                method=method.value,
                url=url
            )
            return self._create_error_result(
                method=method,
                url=url,
                response_time_ms=response_time_ms,
                error="Connection error"
            )

        except requests.exceptions.RequestException as e:
            response_time_ms = (time.time() - start_time) * 1000
            logger.error(
                f"Request failed",
                method=method.value,
                url=url,
                error=str(e)
            )
            return self._create_error_result(
                method=method,
                url=url,
                response_time_ms=response_time_ms,
                error=str(e)
            )

        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            logger.error(
                f"Unexpected error",
                method=method.value,
                url=url,
                error=str(e)
            )
            return self._create_error_result(
                method=method,
                url=url,
                response_time_ms=response_time_ms,
                error=f"Unexpected error: {str(e)}"
            )

    def _prepare_headers(self, custom_headers: Optional[Dict[str, str]]) -> Dict[str, str]:
        """
        Prepare request headers.
        
        Args:
            custom_headers: Custom headers to merge
        
        Returns:
            Merged headers dictionary
        """
        headers = self.session.headers.copy()
        
        if custom_headers:
            headers.update(custom_headers)
        
        return headers

    def _create_error_result(
        self,
        method: HTTPMethod,
        url: str,
        response_time_ms: float,
        error: str
    ) -> RequestResult:
        """
        Create error result.
        
        Args:
            method: HTTP method
            url: Request URL
            response_time_ms: Response time
            error: Error message
        
        Returns:
            RequestResult object
        """
        return RequestResult(
            status_code=0,
            headers={},
            body='',
            response_time_ms=response_time_ms,
            request_url=url,
            request_method=method.value,
            success=False,
            error=error
        )

    def get_with_params(
        self,
        url: str,
        parameter: str,
        value: str,
        headers: Optional[Dict[str, str]] = None
    ) -> RequestResult:
        """
        Send GET request with single parameter.
        
        Args:
            url: Base URL
            parameter: Parameter name
            value: Parameter value
            headers: Custom headers
        
        Returns:
            RequestResult object
        """
        params = {parameter: value}
        return self.get(url, params=params, headers=headers)

    def post_with_json(
        self,
        url: str,
        parameter: str,
        value: str,
        headers: Optional[Dict[str, str]] = None
    ) -> RequestResult:
        """
        Send POST request with JSON data.
        
        Args:
            url: Request URL
            parameter: Parameter name
            value: Parameter value
            headers: Custom headers
        
        Returns:
            RequestResult object
        """
        json_data = {parameter: value}
        return self.post(url, json_data=json_data, headers=headers)

    def build_url_with_params(
        self,
        base_url: str,
        params: Dict[str, str]
    ) -> str:
        """
        Build URL with query parameters.
        
        Args:
            base_url: Base URL
            params: Query parameters
        
        Returns:
            Complete URL with parameters
        """
        if '?' in base_url:
            separator = '&'
        else:
            separator = '?'
        
        query_string = urlencode(params)
        return f"{base_url}{separator}{query_string}"

    def extract_params_from_url(self, url: str) -> Dict[str, List[str]]:
        """
        Extract query parameters from URL.
        
        Args:
            url: URL to parse
        
        Returns:
            Dictionary of parameters
        """
        parsed = urlparse(url)
        return parse_qs(parsed.query)

    def is_valid_url(self, url: str) -> bool:
        """
        Validate URL format.
        
        Args:
            url: URL to validate
        
        Returns:
            True if valid, False otherwise
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    def normalize_url(self, url: str) -> str:
        """
        Normalize URL.
        
        Args:
            url: URL to normalize
        
        Returns:
            Normalized URL
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url.rstrip('/')

    def get_status_text(self, status_code: int) -> str:
        """
        Get HTTP status text.
        
        Args:
            status_code: HTTP status code
        
        Returns:
            Status text
        """
        status_map = {
            200: 'OK',
            201: 'Created',
            204: 'No Content',
            301: 'Moved Permanently',
            302: 'Found',
            304: 'Not Modified',
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            408: 'Request Timeout',
            429: 'Too Many Requests',
            500: 'Internal Server Error',
            502: 'Bad Gateway',
            503: 'Service Unavailable',
            504: 'Gateway Timeout',
        }
        return status_map.get(status_code, 'Unknown')

    def close(self):
        """Close the session."""
        self.session.close()
        logger.info("Request handler session closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


class RequestPool:
    """
    Pool of request handlers for concurrent operations.
    """

    def __init__(self, pool_size: int = 4, config: Optional[RequestConfig] = None):
        """
        Initialize request pool.
        
        Args:
            pool_size: Number of handlers in pool
            config: RequestConfig instance
        """
        self.pool_size = pool_size
        self.config = config or RequestConfig()
        self.handlers = [RequestHandler(config) for _ in range(pool_size)]
        self.current_index = 0

    def get_handler(self) -> RequestHandler:
        """
        Get next handler from pool (round-robin).
        
        Returns:
            RequestHandler instance
        """
        handler = self.handlers[self.current_index]
        self.current_index = (self.current_index + 1) % self.pool_size
        return handler

    def close_all(self):
        """Close all handlers in pool."""
        for handler in self.handlers:
            handler.close()
        logger.info(f"Closed {self.pool_size} request handlers")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close_all()


# Module-level convenience functions
_default_handler: Optional[RequestHandler] = None


def setup_request_handler(config: Optional[RequestConfig] = None) -> RequestHandler:
    """
    Setup default request handler.
    
    Args:
        config: RequestConfig instance
    
    Returns:
        Configured RequestHandler
    """
    global _default_handler
    _default_handler = RequestHandler(config)
    return _default_handler


def get_request_handler() -> RequestHandler:
    """
    Get default request handler.
    
    Returns:
        RequestHandler instance
    """
    global _default_handler
    if _default_handler is None:
        _default_handler = RequestHandler()
    return _default_handler


def http_get(
    url: str,
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None
) -> RequestResult:
    """
    Send GET request using default handler.
    
    Args:
        url: Request URL
        params: Query parameters
        headers: Custom headers
    
    Returns:
        RequestResult object
    """
    handler = get_request_handler()
    return handler.get(url, params=params, headers=headers)


def http_post(
    url: str,
    data: Optional[Dict[str, Any]] = None,
    json_data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None
) -> RequestResult:
    """
    Send POST request using default handler.
    
    Args:
        url: Request URL
        data: Form data
        json_data: JSON data
        headers: Custom headers
    
    Returns:
        RequestResult object
    """
    handler = get_request_handler()
    return handler.post(url, data=data, json_data=json_data, headers=headers)


def http_put(
    url: str,
    data: Optional[Dict[str, Any]] = None,
    json_data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None
) -> RequestResult:
    """
    Send PUT request using default handler.
    
    Args:
        url: Request URL
        data: Form data
        json_data: JSON data
        headers: Custom headers
    
    Returns:
        RequestResult object
    """
    handler = get_request_handler()
    return handler.put(url, data=data, json_data=json_data, headers=headers)


def http_delete(
    url: str,
    headers: Optional[Dict[str, str]] = None
) -> RequestResult:
    """
    Send DELETE request using default handler.
    
    Args:
        url: Request URL
        headers: Custom headers
    
    Returns:
        RequestResult object
    """
    handler = get_request_handler()
    return handler.delete(url, headers=headers)
