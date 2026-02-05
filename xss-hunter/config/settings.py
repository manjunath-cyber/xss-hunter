import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class Settings:
    """XSS Hunter global configuration"""
    
    # Scanning settings
    max_pages: int = 50
    timeout: int = 10
    dedupe_scope: str = 'host'
    
    # Payload settings
    payload_file: str = 'config/payloads.json'
    max_payloads_per_param: int = 10
    
    # Reporting
    output_dir: str = 'reports'
    verbose: bool = False
    
    @classmethod
    def from_env(cls) -> 'Settings':
        """Load settings from environment variables"""
        return cls(
            max_pages=int(os.getenv('XSS_MAX_PAGES', 50)),
            timeout=int(os.getenv('XSS_TIMEOUT', 10)),
            dedupe_scope=os.getenv('XSS_DEDUPE_SCOPE', 'host'),
            verbose=os.getenv('XSS_VERBOSE', 'false').lower() == 'true'
        )
