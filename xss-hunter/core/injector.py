import requests

class Injector:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (XSS Hunter)',
            'X-Scanner': 'XSS Hunter v1.0'
        })
    
    def test(self, inp, payload):
        """test a single injection point with a payload"""
        url = inp['url']
        param = inp['param']
        method = inp.get('method', 'get').lower()
        
        # Prepare parameters
        # We need to preserve other params if possible, but simplest is to just inject target
        # For a real scanner, we'd parse the URL query or form data and replace just the target param.
        # Here we'll do a simple replacement or append.
        
        data = {param: payload}
        
        try:
            if method == 'post':
                resp = self.session.post(url, data=data, timeout=self.timeout)
            else:
                resp = self.session.get(url, params=data, timeout=self.timeout)
            
            # Check reflection
            # A basic reflection check: does the payload appear in the response?
            # Note: This is prone to false positives if the site just echoes back everything escaped.
            # But for this task, we'll check for literal presence.
            # Ideally we check for *unencoded* presence.
            
            if payload in resp.text:
                # Stronger check depending on payload type?
                # For now, return verification.
                return True, f"Payload reflected in response at {url}"
            
            return False, ""
            
        except Exception as e:
            # print(f"[-] Error testing {url}: {e}")
            return False, str(e)
