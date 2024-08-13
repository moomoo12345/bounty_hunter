import asyncio
import logging
from aiohttp import ClientSession, ClientTimeout
from bs4 import BeautifulSoup
from .burp_suite import BurpSuite

class Vulnerabilities:
    def __init__(self):
        self.burp_suite = BurpSuite()
        self.logger = logging.getLogger(__name__)

    async def check_vulnerabilities(self, url, timeout):
        try:
            html = await self.get_response(url, timeout)
            await self.inject_xss_payloads(url)
            await self.inject_sql_payloads(url)
            await self.check_xss(html, url)
            await self.check_sql(html, url)
            await self.check_csrf(html, url)
            await self.check_ssrf(html, url)
            await self.check_open_redirect(html, url)
            await self.check_broken_auth(html, url)
            await self.burp_suite.scan_url(url)
        except Exception as e:
            self.logger.error(f"Error checking vulnerabilities on {url}: {e}")

    async def check_xss(self, html, url):
        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script')
        if scripts:
            self.logger.warning(f"Potential XSS vulnerability found in {url}")

    async def inject_xss_payloads(self, url):
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        for payload in payloads:
            injected_url = f"{url}?q={payload}"
            response = await self.get_response(injected_url, timeout=5)
            if payload in response:
                self.logger.warning(f"Confirmed XSS vulnerability with payload {payload} at {injected_url}")

    async def check_sql(self, html, url):
        error_signatures = ["error in your SQL syntax", "SQL syntax", "database error"]
        if any(sig in html.lower() for sig in error_signatures):
            self.logger.warning(f"Potential SQL Injection vulnerability found in {url}")

    async def inject_sql_payloads(self, url):
        payloads = ["' OR '1'='1", "' OR 'a'='a"]
        for payload in payloads:
            injected_url = f"{url}?q={payload}"
            response = await self.get_response(injected_url, timeout=5)
            if "database error" in response.lower():
                self.logger.warning(f"Confirmed SQL Injection vulnerability with payload {payload} at {injected_url}")

    async def check_csrf(self, html, url):
        if "csrf_token" not in html.lower():
            self.logger.warning(f"Potential CSRF vulnerability found in {url}")

    async def check_ssrf(self, html, url):
        if "external service" in html.lower():
            self.logger.warning(f"Potential SSRF vulnerability found in {url}")

    async def check_open_redirect(self, html, url):
        if "redirect" in html.lower():
            self.logger.warning(f"Potential Open Redirect vulnerability found in {url}")

    async def check_broken_auth(self, html, url):
        if "login failed" in html.lower():
            self.logger.warning(f"Potential Broken Authentication vulnerability found in {url}")

    async def get_response(self, url, timeout):
        retries = 3
        backoff = 1
        for attempt in range(retries):
            try:
                timeout_settings = ClientTimeout(total=timeout)
                async with ClientSession(timeout=timeout_settings) as session:
                    async with session.get(url) as response:
                        return await response.text()
            except (ClientError, TimeoutError) as e:
                self.logger.warning(f"Attempt {attempt+1}: Error fetching {url} - {e}")
                if attempt < retries - 1:
                    await asyncio.sleep(backoff)
                    backoff *= 2  # Exponential backoff
        raise Exception(f"Failed to fetch {url} after {retries} attempts")

    def get_vulnerabilities(self, url):
        return ["XSS", "SQL Injection"]  # Example output, replace with actual findings
