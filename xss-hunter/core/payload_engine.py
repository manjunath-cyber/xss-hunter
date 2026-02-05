import json

class AdvancedPayloadEngine:
    def __init__(self, payload_file='config/payloads.json'):
        with open(payload_file) as f:
            self.payload_db = json.load(f)
        self.mutation_engine = MutationEngine()
    
    def get_payloads_by_context(self, context):
        """Context-specific payloads"""
        context_map = {
            'html': 'html_payloads',
            'attribute': 'attribute_payloads',
            'javascript': 'js_payloads',
            'url': 'url_payloads',
            'dom': 'dom_payloads'
        }
        
        key = context_map.get(context, 'basic')
        return self.payload_db.get(key, [])
    
    def generate_aggressive(self, context):
        """Generate full mutation set"""
        base_payloads = self.get_payloads_by_context(context)
        all_variants = []
        
        for payload in base_payloads:
            all_variants.extend(self.mutation_engine.mutate_all(payload))
        
        # Remove duplicates, limit to 50
        return list(set(all_variants))[:50]
    
    def generate_smart(self, context):
        """Smart escalation: start minimal, increase complexity"""
        base = self.get_payloads_by_context(context)
        
        # Level 1: Basic payloads
        level1 = base[:3]
        
        # Level 2: URL encoded variants
        level2 = [self.mutation_engine.url_encode(p) for p in base[:2]]
        
        # Level 3: HTML entities
        level3 = [self.mutation_engine.html_entity_encode(p) for p in base[:2]]
        
        return level1 + level2 + level3

