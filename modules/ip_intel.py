"""
IP reputation / exposure lookups via Shodan and AbuseIPDB.

Both have free tiers that require a free API key:
- Shodan:    https://account.shodan.io/  (set SHODAN_API_KEY)
- AbuseIPDB: https://www.abuseipdb.com/account/api (set ABUSEIPDB_API_KEY)
"""

import os
import requests

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")


def get_shodan_info(ip):
    if not SHODAN_API_KEY:
        return {"configured": False, "note": "SHODAN_API_KEY not set."}

    url = f"https://api.shodan.io/shodan/host/{ip}"
    try:
        resp = requests.get(url, params={"key": SHODAN_API_KEY}, timeout=10)
        if resp.status_code == 404:
            return {"configured": True, "open_ports": [], "note": "No Shodan data for this IP."}
        resp.raise_for_status()
        data = resp.json()
        return {
            "configured": True,
            "org": data.get("org"),
            "os": data.get("os"),
            "open_ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "vulns": list(data.get("vulns", [])) if data.get("vulns") else [],
        }
    except requests.exceptions.RequestException as e:
        return {"configured": True, "error": str(e)}


def get_abuseipdb_info(ip):
    if not ABUSEIPDB_API_KEY:
        return {"configured": False, "note": "ABUSEIPDB_API_KEY not set."}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "configured": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "is_whitelisted": data.get("isWhitelisted"),
        }
    except requests.exceptions.RequestException as e:
        return {"configured": True, "error": str(e)}
