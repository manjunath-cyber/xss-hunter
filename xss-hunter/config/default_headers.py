import json
import os

def _load_headers():
    """Load default headers from JSON file"""
    file_path = os.path.join(os.path.dirname(__file__), 'default_headers.json')
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Warning: Could not load default_headers.json: {e}")
        return {}

DEFAULT_HEADERS = _load_headers()
