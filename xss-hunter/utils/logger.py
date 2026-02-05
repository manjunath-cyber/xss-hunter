# xss_hunter/utils/logger.py
"""
Logger Module for XSS Hunter
Provides centralized logging configuration for the XSS Hunter project.
Supports file logging, console output, and structured logging.
"""

import logging
import logging.handlers
import os
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any


class JSONFormatter(logging.Formatter):
    """
    Custom formatter that outputs logs in JSON format for better parsing and analysis.
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.
        
        Args:
            record: LogRecord to format
            
        Returns:
            JSON formatted log string
        """
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'process_id': record.process,
            'thread_id': record.thread,
        }

        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        # Add custom attributes
        if hasattr(record, 'extra_data'):
            log_data['extra'] = record.extra_data

        return json.dumps(log_data, default=str)


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter with color support for console output.
    """

    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[41m',   # Red background
    }
    RESET = '\033[0m'

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with color codes.
        
        Args:
            record: LogRecord to format
            
        Returns:
            Formatted log string with color codes
        """
        # Get color for this level
        color = self.COLORS.get(record.levelname, self.RESET)

        # Format the log message
        timestamp = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
        
        # Build colored message
        log_message = (
            f"{color}"
            f"[{timestamp}]"
            f" [{record.levelname:8}]"
            f" {record.name}:"
            f" {record.getMessage()}"
            f"{self.RESET}"
        )

        # Add exception info if present
        if record.exc_info:
            log_message += f"\n{self.formatException(record.exc_info)}"

        return log_message


class XSSHunterLogger:
    """
    Main logger class for XSS Hunter.
    Provides centralized logging configuration and utilities.
    """

    # Singleton instance
    _instance: Optional['XSSHunterLogger'] = None

    def __init__(
        self,
        name: str = 'xss_hunter',
        log_dir: str = 'logs',
        log_level: str = 'INFO',
        enable_file_logging: bool = True,
        enable_console_logging: bool = True,
        json_format: bool = False,
        max_bytes: int = 10 * 1024 * 1024,  # 10 MB
        backup_count: int = 5
    ):
        """
        Initialize XSS Hunter Logger.
        
        Args:
            name: Logger name
            log_dir: Directory for log files
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            enable_file_logging: Enable file logging
            enable_console_logging: Enable console logging
            json_format: Use JSON format for file logs
            max_bytes: Maximum file size before rotation (default 10 MB)
            backup_count: Number of backup files to keep
        """
        self.name = name
        self.log_dir = log_dir
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.enable_file_logging = enable_file_logging
        self.enable_console_logging = enable_console_logging
        self.json_format = json_format
        self.max_bytes = max_bytes
        self.backup_count = backup_count

        # Create logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.log_level)

        # Clear existing handlers
        self.logger.handlers.clear()

        # Create log directory if needed
        if enable_file_logging:
            self._create_log_directory()

        # Add handlers
        if enable_console_logging:
            self._add_console_handler()

        if enable_file_logging:
            self._add_file_handler()
            self._add_scan_handler()

    def _create_log_directory(self):
        """Create log directory if it doesn't exist."""
        log_path = Path(self.log_dir)
        log_path.mkdir(parents=True, exist_ok=True)

    def _add_console_handler(self):
        """Add console handler with colored output."""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.log_level)

        # Use colored formatter for console
        formatter = ColoredFormatter(
            fmt='%(message)s'
        )
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def _add_file_handler(self):
        """Add rotating file handler for general logs."""
        log_file = os.path.join(self.log_dir, f'{self.name}.log')

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count
        )
        file_handler.setLevel(self.log_level)

        # Use JSON formatter or standard formatter
        if self.json_format:
            formatter = JSONFormatter()
        else:
            formatter = logging.Formatter(
                fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )

        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def _add_scan_handler(self):
        """Add separate handler for scan results."""
        scan_log_file = os.path.join(self.log_dir, 'scans.log')

        scan_handler = logging.handlers.RotatingFileHandler(
            scan_log_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count
        )
        scan_handler.setLevel(logging.INFO)

        # Use JSON formatter for scan logs
        formatter = JSONFormatter()
        scan_handler.setFormatter(formatter)

        # Create separate logger for scans
        scan_logger = logging.getLogger(f'{self.name}.scans')
        scan_logger.addHandler(scan_handler)
        scan_logger.setLevel(logging.INFO)

    def get_logger(self) -> logging.Logger:
        """
        Get the configured logger instance.
        
        Returns:
            logging.Logger instance
        """
        return self.logger

    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self._log('debug', message, **kwargs)

    def info(self, message: str, **kwargs):
        """Log info message."""
        self._log('info', message, **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self._log('warning', message, **kwargs)

    def error(self, message: str, **kwargs):
        """Log error message."""
        self._log('error', message, **kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message."""
        self._log('critical', message, **kwargs)

    def _log(self, level: str, message: str, **kwargs):
        """
        Internal logging method with extra data support.
        
        Args:
            level: Log level (debug, info, warning, error, critical)
            message: Log message
            **kwargs: Extra data to include in log
        """
        # Create LogRecord with extra data
        if kwargs:
            extra = {'extra_data': kwargs}
        else:
            extra = {}

        # Get appropriate logging method
        log_method = getattr(self.logger, level)
        log_method(message, extra=extra if extra else None)

    def log_scan_start(self, scan_id: str, endpoints: int, **kwargs):
        """
        Log scan start event.
        
        Args:
            scan_id: Unique scan identifier
            endpoints: Number of endpoints to scan
            **kwargs: Additional metadata
        """
        message = f"Scan started: {scan_id} - Endpoints: {endpoints}"
        self.info(message, scan_id=scan_id, endpoints=endpoints, **kwargs)

    def log_scan_end(self, scan_id: str, duration: float, vulnerabilities: int, **kwargs):
        """
        Log scan completion event.
        
        Args:
            scan_id: Unique scan identifier
            duration: Scan duration in seconds
            vulnerabilities: Total vulnerabilities found
            **kwargs: Additional metadata
        """
        message = (
            f"Scan completed: {scan_id} - "
            f"Duration: {duration}s - "
            f"Vulnerabilities: {vulnerabilities}"
        )
        self.info(message, scan_id=scan_id, duration=duration, vulnerabilities=vulnerabilities, **kwargs)

    def log_endpoint_scan(self, endpoint_url: str, method: str, status: str, **kwargs):
        """
        Log endpoint scan progress.
        
        Args:
            endpoint_url: API endpoint URL
            method: HTTP method
            status: Scan status (STARTED, COMPLETED, FAILED)
            **kwargs: Additional metadata
        """
        message = f"Endpoint scan: {method} {endpoint_url} - {status}"
        self.debug(message, endpoint=endpoint_url, method=method, status=status, **kwargs)

    def log_vulnerability_found(
        self,
        scan_id: str,
        endpoint_url: str,
        parameter: str,
        vuln_type: str,
        severity: str,
        payload: str,
        **kwargs
    ):
        """
        Log vulnerability discovery.
        
        Args:
            scan_id: Unique scan identifier
            endpoint_url: Vulnerable endpoint
            parameter: Vulnerable parameter name
            vuln_type: Type of vulnerability (Reflected XSS, etc.)
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            payload: Payload that triggered vulnerability
            **kwargs: Additional metadata
        """
        message = (
            f"Vulnerability found - "
            f"Type: {vuln_type}, "
            f"Severity: {severity}, "
            f"Endpoint: {endpoint_url}, "
            f"Parameter: {parameter}"
        )

        if severity in ['CRITICAL', 'HIGH']:
            self.error(
                message,
                scan_id=scan_id,
                endpoint=endpoint_url,
                parameter=parameter,
                vuln_type=vuln_type,
                severity=severity,
                payload=payload[:100],  # Log first 100 chars of payload
                **kwargs
            )
        else:
            self.warning(
                message,
                scan_id=scan_id,
                endpoint=endpoint_url,
                parameter=parameter,
                vuln_type=vuln_type,
                severity=severity,
                payload=payload[:100],
                **kwargs
            )

    def log_request(
        self,
        method: str,
        url: str,
        status_code: int,
        response_time_ms: float,
        **kwargs
    ):
        """
        Log HTTP request details.
        
        Args:
            method: HTTP method
            url: Request URL
            status_code: Response status code
            response_time_ms: Response time in milliseconds
            **kwargs: Additional metadata
        """
        message = f"Request: {method} {url} - Status: {status_code} - Time: {response_time_ms}ms"
        
        if status_code >= 400:
            self.warning(message, method=method, url=url, status_code=status_code, response_time=response_time_ms, **kwargs)
        else:
            self.debug(message, method=method, url=url, status_code=status_code, response_time=response_time_ms, **kwargs)

    def log_error_with_context(
        self,
        error_message: str,
        error_type: str,
        context: Dict[str, Any],
        **kwargs
    ):
        """
        Log error with full context information.
        
        Args:
            error_message: Error description
            error_type: Type of error
            context: Additional context dictionary
            **kwargs: Additional metadata
        """
        message = f"{error_type}: {error_message}"
        self.error(message, error_type=error_type, context=context, **kwargs)

    def log_performance_metrics(
        self,
        metric_name: str,
        value: float,
        unit: str,
        **kwargs
    ):
        """
        Log performance metrics.
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            unit: Unit of measurement
            **kwargs: Additional metadata
        """
        message = f"Performance: {metric_name} = {value} {unit}"
        self.info(message, metric_name=metric_name, value=value, unit=unit, **kwargs)

    @classmethod
    def get_instance(cls, **kwargs) -> 'XSSHunterLogger':
        """
        Get or create singleton logger instance.
        
        Args:
            **kwargs: Arguments for logger initialization
            
        Returns:
            XSSHunterLogger instance
        """
        if cls._instance is None:
            cls._instance = cls(**kwargs)
        return cls._instance

    @classmethod
    def reset_instance(cls):
        """Reset singleton instance."""
        cls._instance = None


# Module-level convenience functions
_logger: Optional[XSSHunterLogger] = None


def setup_logging(
    name: str = 'xss_hunter',
    log_dir: str = 'logs',
    log_level: str = 'INFO',
    enable_file_logging: bool = True,
    enable_console_logging: bool = True,
    json_format: bool = False,
) -> XSSHunterLogger:
    """
    Setup global logger.
    
    Args:
        name: Logger name
        log_dir: Log directory path
        log_level: Logging level
        enable_file_logging: Enable file logging
        enable_console_logging: Enable console logging
        json_format: Use JSON format for logs
        
    Returns:
        Configured XSSHunterLogger instance
    """
    global _logger
    _logger = XSSHunterLogger(
        name=name,
        log_dir=log_dir,
        log_level=log_level,
        enable_file_logging=enable_file_logging,
        enable_console_logging=enable_console_logging,
        json_format=json_format,
    )
    return _logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get logger instance.
    
    Args:
        name: Specific logger name (optional)
        
    Returns:
        logging.Logger instance
    """
    global _logger
    if _logger is None:
        _logger = setup_logging()
    
    if name:
        return logging.getLogger(name)
    return _logger.get_logger()


def log_info(message: str, **kwargs):
    """Log info message."""
    global _logger
    if _logger is None:
        _logger = setup_logging()
    _logger.info(message, **kwargs)


def log_debug(message: str, **kwargs):
    """Log debug message."""
    global _logger
    if _logger is None:
        _logger = setup_logging()
    _logger.debug(message, **kwargs)


def log_warning(message: str, **kwargs):
    """Log warning message."""
    global _logger
    if _logger is None:
        _logger = setup_logging()
    _logger.warning(message, **kwargs)


def log_error(message: str, **kwargs):
    """Log error message."""
    global _logger
    if _logger is None:
        _logger = setup_logging()
    _logger.error(message, **kwargs)


def log_critical(message: str, **kwargs):
    """Log critical message."""
    global _logger
    if _logger is None:
        _logger = setup_logging()
    _logger.critical(message, **kwargs)
