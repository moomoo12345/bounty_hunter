# Bounty Hunter

Bounty Hunter is a comprehensive web vulnerability scanning tool designed for bug bounty hunters. It scans web applications for common vulnerabilities like XSS, SQL Injection, CSRF, SSRF, and more.

## Features

- **Asynchronous Scanning**: Fast and efficient scanning with asyncio.
- **Vulnerability Checks**: XSS, SQL Injection, CSRF, SSRF, Open Redirect, Broken Authentication.
- **BurpSuite Integration**: Mock Burp Suite scanning (replace with real API if available).
- **Concurrency Control**: Manage the number of concurrent requests.
- **Reporting**: Generates a detailed report of found vulnerabilities.

## Installation

```bash
git clone https://github.com/moomoo12345/bounty_hunter.git
cd bounty_hunter
pip install -r requirements.txt
pip install .
