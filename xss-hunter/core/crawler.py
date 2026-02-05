import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from collections import defaultdict

class SmartCrawler:
    def __init__(self, target_url, max_pages=50):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.visited_urls = set()
        self.to_crawl = [target_url]
        self.max_pages = max_pages
        self.links = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (XSS Hunter)'
        })
    
    def crawl(self):
        """Crawl target domain respecting scope"""
        while self.to_crawl and len(self.visited_urls) < self.max_pages:
            url = self.to_crawl.pop(0)
            
            if url in self.visited_urls:
                continue
            
            if not self._is_same_domain(url):
                continue
            
            self.visited_urls.add(url)
            print(f"[*] Crawling: {url}")
            
            try:
                resp = self.session.get(url, timeout=10)
                soup = BeautifulSoup(resp.text, 'lxml')
                
                # Extract all links
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href'])
                    if full_url not in self.visited_urls:
                        self.to_crawl.append(full_url)
                        self.links.append(full_url)
            except Exception as e:
                print(f"[!] Error crawling {url}: {e}")
        
        return self.visited_urls
    
    def _is_same_domain(self, url):
        """Check if URL is in same domain"""
        return urlparse(url).netloc == self.domain
