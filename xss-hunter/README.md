# XSS Hunter

Professional XSS Vulnerability Scanner.

## Browser Requirements

### Firefox (Recommended)
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install firefox-geckodriver

# macOS
brew install firefox geckodriver

# Windows
# Download Firefox from https://www.mozilla.org/firefox/
# GeckoDriver from https://github.com/mozilla/geckodriver/releases
# WebDriver Manager handles this automatically (no manual download needed).

# WebDriver Manager (automatic)
pip install webdriver-manager
```

## Usage
```bash
python xss_hunter.py -u https://target.com --dom --crawl
```
Note: `--dom` flag enables headless Firefox for DOM XSS testing.
