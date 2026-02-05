from urllib.parse import urlparse

class ParamDeduplicator:
    def __init__(self, dedupe_scope='host'):
        """
        dedupe_scope: 'none', 'host', or 'path'
        'host': dedupe same param across entire domain
        'path': dedupe only within same endpoint
        """
        self.dedupe_scope = dedupe_scope
        self.tested_signatures = set()
    
    def get_signature(self, url, param_name, context_type):
        """Generate unique parameter signature"""
        parsed = urlparse(url)
        
        if self.dedupe_scope == 'none':
            return None
        elif self.dedupe_scope == 'host':
            return f"{parsed.netloc}|{param_name}|{context_type}"
        elif self.dedupe_scope == 'path':
            return f"{parsed.netloc}{parsed.path}|{param_name}|{context_type}"
        
        return None
    
    def is_tested(self, url, param_name, context_type):
        """Check if parameter already tested"""
        sig = self.get_signature(url, param_name, context_type)
        return sig in self.tested_signatures if sig else False
    
    def mark_tested(self, url, param_name, context_type):
        """Mark parameter as tested"""
        sig = self.get_signature(url, param_name, context_type)
        if sig:
            self.tested_signatures.add(sig)
    
    def stats(self):
        """Get deduplication statistics"""
        return {
            'scope': self.dedupe_scope,
            'tested_unique': len(self.tested_signatures)
        }
