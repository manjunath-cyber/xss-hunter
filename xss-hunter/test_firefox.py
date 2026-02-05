#!/usr/bin/env python3
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from webdriver_manager.firefox import GeckoDriverManager
from selenium.webdriver.firefox.service import Service
import sys

def test_firefox():
    print("Initializing Firefox options...")
    options = Options()
    options.add_argument("--headless")

    print("Installing/Finding GeckoDriver...")
    try:
        service_path = GeckoDriverManager().install()
        print(f"GeckoDriver path: {service_path}")
        service = Service(service_path)
    except Exception as e:
        print(f"Failed to install GeckoDriver: {e}")
        return

    print("Starting Firefox driver...")
    try:
        driver = webdriver.Firefox(service=service, options=options)
    except Exception as e:
        print(f"Failed to start Firefox driver: {e}")
        return

    try:
        print("Navigating to mozilla.org...")
        driver.get("https://www.mozilla.org")
        user_agent = driver.execute_script('return navigator.userAgent')
        print(f"✅ Firefox version: {user_agent}")
        print("Firefox DOM testing ready!")
    except Exception as e:
        print(f"Error during navigation/execution: {e}")
    finally:
        print("Closing driver...")
        driver.quit()

if __name__ == "__main__":
    test_firefox()
