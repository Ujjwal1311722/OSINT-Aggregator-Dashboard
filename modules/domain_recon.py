"""
Domain reconnaissance helpers.

- WHOIS lookup via python-whois
- Subdomain enumeration via crt.sh certificate transparency logs (no API key needed)
- Basic DNS record lookup via dnspython
"""

import requests
import whois
import dns.resolver


def get_whois(domain):
    """Return basic WHOIS fields for a domain. Returns an error dict on failure."""
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "org": getattr(w, "org", None),
            "country": getattr(w, "country", None),
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}


def get_subdomains_crtsh(domain, limit=50):
    """
    Query crt.sh certificate transparency logs for subdomains.
    Free, no API key required. crt.sh is a community-run, often-overloaded
    service, so we use a longer timeout and one retry before giving up.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    last_error = None

    for attempt in range(2):
        try:
            resp = requests.get(url, timeout=25)
            resp.raise_for_status()
            data = resp.json()
            subdomains = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domain):
                        subdomains.add(sub)
            return sorted(subdomains)[:limit]
        except Exception as e:
            last_error = e

    return [f"crt.sh lookup failed after retry: {last_error}"]


def get_dns_records(domain):
    """
    Fetch common DNS record types for a domain.
    Falls back to public resolvers (Google/Cloudflare) if the system
    resolver fails, and reports the real error per record type instead
    of silently returning an empty list — much easier to debug network
    issues that way.
    """
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8
    # Fall back to well-known public resolvers in case the system/VPN
    # resolver is blocked, slow, or misconfigured.
    resolver.nameservers = resolver.nameservers + ["8.8.8.8", "1.1.1.1"]

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except dns.resolver.NXDOMAIN:
            records[rtype] = []
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except Exception as e:
            records[rtype] = [f"lookup error: {e}"]
    return records
# """
# Domain reconnaissance helpers.

# - WHOIS lookup via python-whois
# - Subdomain enumeration via crt.sh certificate transparency logs (no API key needed)
# - Basic DNS record lookup via dnspython
# """

# import requests
# import whois
# import dns.resolver


# def get_whois(domain):
#     """Return basic WHOIS fields for a domain. Returns an error dict on failure."""
#     try:
#         w = whois.whois(domain)
#         return {
#             "registrar": w.registrar,
#             "creation_date": str(w.creation_date),
#             "expiration_date": str(w.expiration_date),
#             "name_servers": w.name_servers,
#             "org": getattr(w, "org", None),
#             "country": getattr(w, "country", None),
#         }
#     except Exception as e:
#         return {"error": f"WHOIS lookup failed: {e}"}


# def get_subdomains_crtsh(domain, limit=50):
#     """
#     Query crt.sh certificate transparency logs for subdomains.
#     Free, no API key required. crt.sh can be slow/rate-limited at times.
#     """
#     url = f"https://crt.sh/?q=%25.{domain}&output=json"
#     try:
#         resp = requests.get(url, timeout=15)
#         resp.raise_for_status()
#         data = resp.json()
#         subdomains = set()
#         for entry in data:
#             name_value = entry.get("name_value", "")
#             for sub in name_value.split("\n"):
#                 sub = sub.strip().lstrip("*.")
#                 if sub.endswith(domain):
#                     subdomains.add(sub)
#         return sorted(subdomains)[:limit]
#     except Exception as e:
#         return [f"crt.sh lookup failed: {e}"]


# def get_dns_records(domain):
#     """Fetch common DNS record types for a domain."""
#     records = {}
#     record_types = ["A", "AAAA", "MX", "NS", "TXT"]
#     resolver = dns.resolver.Resolver()
#     resolver.timeout = 5
#     resolver.lifetime = 5

#     for rtype in record_types:
#         try:
#             answers = resolver.resolve(domain, rtype)
#             records[rtype] = [str(r) for r in answers]
#         except Exception:
#             records[rtype] = []
#     return records
