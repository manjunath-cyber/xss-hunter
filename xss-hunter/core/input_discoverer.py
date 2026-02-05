from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class InputDiscoverer:
    def __init__(self):
        self.seen_forms = set()
    
    def discover(self, url):
        """Discover inputs from URL"""
        inputs = []
        
        # 1. URL Parameters
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    name = param.split('=')[0]
                    inputs.append({
                        'url': url,
                        'param': name,
                        'context': 'url'
                    })
        
        # 2. Forms (requires fetching, but we might just extract if we had HTML)
        # Since this is a simple discoverer, we'll assume the crawler might pass content 
        # or we fetch here. The main loop passes a URL.
        try:
            import requests # Lazy import to avoid circular dependency if any
            resp = requests.get(url, timeout=5)
            soup = BeautifulSoup(resp.text, 'lxml')
            
            for form in soup.find_all('form'):
                action = form.get('action') or ''
                form_url = urljoin(url, action)
                method = form.get('method', 'get').lower()
                
                for input_tag in form.find_all(['input', 'textarea']):
                    name = input_tag.get('name')
                    if not name:
                        continue
                    
                    inputs.append({
                        'url': form_url,
                        'param': name,
                        'context': 'html', # Defaulting to HTML context for form inputs
                        'method': method
                    })
        except Exception as e:
            print(f"[!] Error discovering inputs on {url}: {e}")
            
        return inputs
