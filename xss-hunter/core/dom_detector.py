from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
import time

class DOMXSSDetector:
    def __init__(self):
        self.driver = None
        # Try Firefox first (Kali default)
        try:
            options = FirefoxOptions()
            options.add_argument("--headless")
            service = FirefoxService(GeckoDriverManager().install())
            self.driver = webdriver.Firefox(service=service, options=options)
        except Exception as e:
            print(f"[*] Firefox initialization failed: {e}. Trying Chrome...")
            
        if not self.driver:
            try:
                options = ChromeOptions()
                options.add_argument("--headless")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                service = ChromeService(ChromeDriverManager().install())
                self.driver = webdriver.Chrome(service=service, options=options)
            except Exception as e:
                print(f"[!] Failed to initialize any browser: {e}")
                raise e
    
    def test_dom_xss(self, url, payload, param_name):
        """Test DOM XSS with marker detection"""
        # Inject marker into payload
        test_payload = f"window.__xss_marker='{param_name}';{payload}"
        test_url = f"{url}#{test_payload}" if '#' not in url else f"{url}&{test_payload}"
        
        try:
            self.driver.get(test_url)
            time.sleep(3)  # Wait for JS execution
            
            # Check marker
            marker = self.driver.execute_script("return window.__xss_marker;")
            if marker == param_name:
                return True, "DOM XSS Confirmed"
            
            # Check alert execution
            try:
                alert_text = self.driver.switch_to.alert.text
                self.driver.switch_to.alert.accept()
                return True, "Alert Executed"
            except:
                pass
            
            # Check payload in source
            if payload.lower() in self.driver.page_source.lower():
                return True, "Payload in DOM"
            
            return False, "No execution"
        except Exception as e:
            return False, str(e)
    
    def close(self):
        self.driver.quit()
