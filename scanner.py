import asyncio
import logging
from .vulnerabilities import Vulnerabilities
from .utils import resolve_domain, get_urls

class Scanner:
    def __init__(self, target_domains, timeout=10, logging_level=logging.INFO, rate_limit=5):
        self.target_domains = target_domains
        self.vulnerabilities = Vulnerabilities()
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.semaphore = asyncio.Semaphore(rate_limit)
        logging.basicConfig(level=logging_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    async def perform_scan(self):
        tasks = [self.check_vulnerabilities(domain) for domain in self.target_domains]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def check_vulnerabilities(self, domain):
        async with self.semaphore:
            try:
                urls = get_urls(domain)
                for url in urls:
                    await self.vulnerabilities.check_vulnerabilities(url, self.timeout)
            except Exception as e:
                self.logger.error(f"Error checking domain {domain}: {e}")

    def generate_report(self):
        report = ""
        for domain in self.target_domains:
            report += f"Domain: {domain}\n"
            for url in get_urls(domain):
                report += f"URL: {url}\n"
                vulnerabilities = self.vulnerabilities.get_vulnerabilities(url)
                if vulnerabilities:
                    report += "Vulnerabilities:\n"
                    for vulnerability in vulnerabilities:
                        report += f"- {vulnerability}\n"
                else:
                    report += "No vulnerabilities found.\n"
                report += "\n"
        return report
