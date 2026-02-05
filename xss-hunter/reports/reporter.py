import json
import html
from utils.logger import get_logger

class Reporter:
    def __init__(self, target_url):
        self.logger = get_logger('xss_hunter.reports')
        self.target_url = target_url
        self.findings = []
    
    def add_finding(self, inp, payload, evidence, severity='High'):
        finding = {
            'target': self.target_url,
            'url': inp['url'],
            'parameter': inp['param'],
            'payload': payload,
            'evidence': evidence,
            'severity': severity
        }
        self.findings.append(finding)
    
    def export_json(self, filename):
        try:
            self.logger.info(f"Exporting JSON report to {filename}")
            with open(filename, 'w') as f:
                json.dump(self.findings, f, indent=4)
        except Exception as e:
            self.logger.error(f"Error exporting JSON: {e}")
            print(f"[!] Error exporting JSON: {e}")
    
    def export_markdown(self, filename):
        try:
            with open(filename, 'w') as f:
                f.write(f"# XSS Hunter Report\n\n")
                f.write(f"**Target:** {self.target_url}\n")
                f.write(f"**Findings:** {len(self.findings)}\n\n")
                
                for i, find in enumerate(self.findings, 1):
                    f.write(f"## Finding #{i}\n")
                    f.write(f"- **URL:** `{find['url']}`\n")
                    f.write(f"- **Parameter:** `{find['parameter']}`\n")
                    f.write(f"- **Severity:** {find['severity']}\n")
                    f.write(f"- **Payload:**\n```\n{find['payload']}\n```\n")
                    f.write(f"- **Evidence:** {find['evidence']}\n\n")
        except Exception as e:
            print(f"[!] Error exporting Markdown: {e}")

    def export_html(self, filename):
        try:
            with open(filename, 'w') as f:
                f.write("<html><head><title>XSS Report</title>")
                f.write("<style>body{font-family:sans-serif;padding:20px}.finding{border:1px solid #ccc;padding:15px;margin-bottom:20px;border-radius:5px;background:#f9f9f9}h2{color:#d32f2f}</style>")
                f.write("</head><body>")
                f.write(f"<h1>XSS Hunter Report</h1><p>Target: {html.escape(self.target_url)}</p>")
                f.write(f"<p>Findings: {len(self.findings)}</p>")
                
                for i, find in enumerate(self.findings, 1):
                    f.write(f"<div class='finding'><h2>Finding #{i}</h2>")
                    f.write(f"<p><strong>URL:</strong> {html.escape(find['url'])}</p>")
                    f.write(f"<p><strong>Parameter:</strong> {html.escape(find['parameter'])}</p>")
                    f.write(f"<p><strong>Severity:</strong> {html.escape(find['severity'])}</p>")
                    f.write(f"<p><strong>Payload:</strong> <pre>{html.escape(find['payload'])}</pre></p>")
                    f.write(f"<p><strong>Evidence:</strong> {html.escape(find['evidence'])}</p>")
                    f.write("</div>")
                
                f.write("</body></html>")
        except Exception as e:
            print(f"[!] Error exporting HTML: {e}")
