import requests
import re
import asyncio
import aiohttp
import logging
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

class XSSScanner:
    def __init__(self, target_url, auth_cookie=None, custom_headers=None):
        self.target_url = target_url
        self.auth_cookie = auth_cookie
        self.custom_headers = custom_headers or {}
        self.visited_links = set()
        self.vulnerable_links = set()
        self.vulnerable_payloads = []

    async def scan_url(self, session, url, custom_payloads=None):
        try:
            headers = self.custom_headers.copy()
            if self.auth_cookie:
                headers['Cookie'] = self.auth_cookie

            async with session.get(url, headers=headers) as response:
                response.raise_for_status()
                page_source = await response.text()
                soup = BeautifulSoup(page_source, "html.parser")
                scripts = soup.find_all(string=re.compile(r'<script|javascript:|data:|on\w+\s*='))
                if scripts:
                    self.vulnerable_links.add(url)
                    print(f"Potential XSS vulnerability detected at: {url}")
                    # Log the vulnerable page source for further analysis
                    with open(f"vulnerable_{url.replace('/', '_')}.html", "w", encoding="utf-8") as f:
                        f.write(page_source)

                    # Extract and log vulnerable payloads
                    for script in scripts:
                        for payload in custom_payloads:
                            if payload in script:
                                self.vulnerable_payloads.append(payload)
                                print(f"Vulnerable payload '{payload}' detected in: {url}")
                self.visited_links.add(url)
        except Exception as e:
            print(f"Error scanning {url}: {e}")

    async def crawl_and_scan(self, max_depth=3, custom_payloads=None):
        await self._crawl_and_scan_recursive(self.target_url, max_depth, custom_payloads)

    async def _crawl_and_scan_recursive(self, url, depth, custom_payloads):
        if depth == 0 or url in self.visited_links:
            return

        async with aiohttp.ClientSession() as session:
            await self.scan_url(session, url, custom_payloads)

            try:
                async with session.get(url) as response:
                    response.raise_for_status()
                    page_source = await response.text()
                    soup = BeautifulSoup(page_source, "html.parser")
                    links = [link.get("href") for link in soup.find_all("a")]
                    for link in links:
                        if link and not link.startswith("http"):
                            link = f"{self.target_url}/{link}"
                        await self._crawl_and_scan_recursive(link, depth - 1, custom_payloads)
            except Exception as e:
                print(f"Error fetching links from {url}: {e}")

    def report_vulnerabilities(self):
        print("\nSummary:")
        print(f"Scanned {len(self.visited_links)} pages.")
        if self.vulnerable_links:
            print(f"Found {len(self.vulnerable_links)} potential XSS vulnerabilities:")
            for url in self.vulnerable_links:
                print(f"- {url}")
            print("\nVulnerable Payloads:")
            for payload in self.vulnerable_payloads:
                print(f"- {payload}")
        else:
            print("No XSS vulnerabilities detected.")

if __name__ == "__main__":
    target_url = input("Enter the URL to scan: ")
    custom_payloads = input("Enter custom payloads (comma-separated): ").split(",")

    # Optional: Provide authentication cookie for scanning authenticated areas
    auth_cookie = input("Enter authentication cookie (if applicable): ")

    # Optional: Provide custom HTTP headers for requests
    custom_headers = {}
    custom_headers_input = input("Enter custom headers (key1:value1,key2:value2): ")
    if custom_headers_input:
        header_pairs = custom_headers_input.split(",")
        for pair in header_pairs:
            key, value = pair.split(":")
            custom_headers[key.strip()] = value.strip()

    scanner = XSSScanner(target_url, auth_cookie=auth_cookie, custom_headers=custom_headers)

    # Setup logging
    logging.basicConfig(filename="xss_scan.log", level=logging.INFO)

    print("Scanning for XSS vulnerabilities...")

    loop = asyncio.get_event_loop()
    loop.run_until_complete(scanner.crawl_and_scan(max_depth=3, custom_payloads=custom_payloads))
    scanner.report_vulnerabilities()
