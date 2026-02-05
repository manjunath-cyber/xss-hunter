import json
import os

def load_payloads(file_path=None):
    """Load payloads from JSON file"""
    if file_path is None:
        file_path = os.path.join(os.path.dirname(__file__), 'payloads.json')
        
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Error loading payloads from {file_path}: {e}")
        return {}
