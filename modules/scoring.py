"""
Lightweight, transparent risk-scoring heuristics.

These are intentionally simple (rule-based, not ML) so they're easy to
explain in an interview: "a domain with N exposed subdomains and an open
RDP port scores higher than one with neither."

Scores are 0-100, where higher = more exposure/risk.
"""


def score_domain(result):
    score = 0
    subdomains = result.get("subdomains", [])
    if isinstance(subdomains, list):
        score += min(len(subdomains) * 2, 40)

    dns_records = result.get("dns_records", {})
    if dns_records.get("TXT"):
        # SPF/DKIM/verification records leak info about third-party services in use
        score += 5

    whois_data = result.get("whois", {})
    if isinstance(whois_data, dict) and not whois_data.get("error"):
        score += 5  # WHOIS data successfully retrieved = some public exposure

    return min(score, 100)


def score_breach(breach_data):
    # XposedOrNot returns its own risk_score (0-100) when it has data;
    # fall back to a simple count-based heuristic otherwise.
    if breach_data.get("risk_score") is not None:
        return min(breach_data["risk_score"], 100)
    breaches = breach_data.get("breaches", [])
    return min(len(breaches) * 20, 100)


def score_ip(result):
    score = 0
    shodan = result.get("shodan", {})
    if shodan.get("configured"):
        open_ports = shodan.get("open_ports", [])
        score += min(len(open_ports) * 5, 40)
        if shodan.get("vulns"):
            score += min(len(shodan["vulns"]) * 10, 40)

    abuse = result.get("abuseipdb", {})
    if abuse.get("configured"):
        confidence = abuse.get("abuse_confidence_score") or 0
        score += min(confidence // 2, 20)

    return min(score, 100)


def score_metadata(meta):
    score = 0
    # Images: GPS coordinates are the biggest leak
    if meta.get("has_location_data"):
        score += 60
    if meta.get("exif"):
        score += 20

    # PDFs: embedded JavaScript is a known malicious-PDF vector;
    # author/producer fields are a smaller but real metadata leak
    pdf_meta = meta.get("pdf_meta")
    if pdf_meta:
        if pdf_meta.get("has_embedded_javascript"):
            score += 70
        if pdf_meta.get("author") or pdf_meta.get("creator"):
            score += 15

    # ZIP archives: encrypted entries are a smaller signal (could be benign
    # or could be hiding something); a very large internal listing exposes
    # more of the original folder/username structure
    zip_meta = meta.get("zip_meta")
    if zip_meta:
        if zip_meta.get("any_encrypted"):
            score += 20
        score += min(zip_meta.get("entry_count", 0) // 5, 30)

    # Text files: any exposed email or IP address is a real, immediate leak
    txt_meta = meta.get("txt_meta")
    if txt_meta:
        score += min(len(txt_meta.get("emails_found", [])) * 15, 45)
        score += min(len(txt_meta.get("ips_found", [])) * 10, 30)

    return min(score, 100)


def risk_label(score):
    if score >= 70:
        return "High"
    elif score >= 35:
        return "Medium"
    return "Low"
