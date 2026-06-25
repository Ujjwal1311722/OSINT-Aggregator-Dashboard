"""
Email breach checking via the XposedOrNot API.

XposedOrNot (https://xposedornot.com) is a free, open-source breach-checking
service — no signup and no API key required for email lookups, just a
2 requests/second rate limit. This replaces Have I Been Pwned, whose
breach-search API now requires a paid subscription.

We use the `breach-analytics` endpoint since it returns richer detail
(per-breach description, exposed data types, a built-in risk score) than
the plain check-email endpoint.
"""

import requests

XON_ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics"


def check_email(email):
    """
    Check whether an email appears in known breaches via XposedOrNot.
    Returns a dict: {email, configured, breaches: [...], risk_label, risk_score}.
    `configured` is always True here since no API key is needed, but the key
    is kept for template/scoring compatibility with the old HIBP-based shape.
    """
    try:
        resp = requests.get(XON_ANALYTICS_URL, params={"email": email}, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        exposed = data.get("ExposedBreaches")
        if not exposed:
            return {"email": email, "configured": True, "breaches": [], "risk_score": 0, "risk_label": "Low"}

        breach_list = exposed.get("breaches_details", [])
        breaches = [
            {
                "name": b.get("breach"),
                "breach_date": b.get("xposed_date"),
                "data_classes": (b.get("xposed_data") or "").split(";"),
                "description": b.get("details"),
            }
            for b in breach_list
        ]

        risk_info = (data.get("BreachMetrics") or {}).get("risk", [{}])
        risk_info = risk_info[0] if risk_info else {}

        return {
            "email": email,
            "configured": True,
            "breaches": breaches,
            "risk_score": risk_info.get("risk_score", min(len(breaches) * 20, 100)),
            "risk_label": risk_info.get("risk_label"),
        }
    except requests.exceptions.RequestException as e:
        return {"email": email, "configured": True, "breaches": [], "error": str(e)}
