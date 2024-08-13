import argparse
import asyncio
from bounty_hunter.scanner import Scanner
from bounty_hunter.config import Config

def main():
    parser = argparse.ArgumentParser(description="Bounty Hunter - Web Vulnerability Scanner")
    parser.add_argument("--domains", nargs="+", help="List of domains to scan", required=False, default=Config.TARGET_DOMAINS)
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds", required=False, default=Config.TIMEOUT)
    parser.add_argument("--rate-limit", type=int, help="Number of concurrent requests", required=False, default=Config.RATE_LIMIT)
    args = parser.parse_args()

    scanner = Scanner(target_domains=args.domains, timeout=args.timeout, rate_limit=args.rate_limit)
    asyncio.run(scanner.perform_scan())
    print(scanner.generate_report())

if __name__ == "__main__":
    main()
