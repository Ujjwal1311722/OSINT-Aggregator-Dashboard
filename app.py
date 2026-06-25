"""
OSINT Intelligence Aggregator Dashboard
-----------------------------------------
Educational / authorized-use OSINT tool. Aggregates publicly available
intelligence about a domain, email, IP, or uploaded file into a single
dashboard with a basic exposure/risk score.

IMPORTANT: Only use this tool against assets you own or are explicitly
authorized to test. Running OSINT lookups against third parties without
permission may violate terms of service or local law.
"""

import os
import sqlite3
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()  # reads .env in the project root and populates os.environ

from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename

from modules import domain_recon, breach_check, ip_intel, metadata_extract, scoring

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-me")

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "docx", "zip", "txt"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

DB_PATH = os.path.join(os.path.dirname(__file__), "osint_cache.db")


def init_db():
    """Create the results-cache table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS lookups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT NOT NULL,
            target_value TEXT NOT NULL,
            result_json TEXT NOT NULL,
            risk_score INTEGER,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def cache_result(target_type, target_value, result_json, risk_score):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO lookups (target_type, target_value, result_json, risk_score, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (target_type, target_value, result_json, risk_score, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def normalize_domain(raw):
    """
    Accept user input loosely (full URL, trailing slash, www prefix, etc.)
    and reduce it to a bare hostname suitable for WHOIS/DNS/crt.sh lookups.
    e.g. "https://web.whatsapp.com/path?x=1" -> "web.whatsapp.com"
    """
    value = raw.strip()
    # Strip scheme (http://, https://, ftp://, etc.)
    if "://" in value:
        value = value.split("://", 1)[1]
    # Drop any path, query string, or fragment
    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    value = value.split("#", 1)[0]
    # Drop a port if present (e.g. example.com:8080)
    value = value.split(":", 1)[0]
    return value.lower().strip()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/lookup/domain", methods=["POST"])
def lookup_domain():
    domain = request.form.get("domain", "").strip()
    if not domain:
        flash("Please enter a domain.")
        return redirect(url_for("index"))

    domain = normalize_domain(domain)

    whois_data = domain_recon.get_whois(domain)
    subdomains = domain_recon.get_subdomains_crtsh(domain)
    dns_records = domain_recon.get_dns_records(domain)

    result = {
        "domain": domain,
        "whois": whois_data,
        "subdomains": subdomains,
        "dns_records": dns_records,
    }
    risk = scoring.score_domain(result)
    import json
    cache_result("domain", domain, json.dumps(result), risk)

    return render_template("results.html", result_type="domain", result=result, risk=risk)


@app.route("/lookup/breach", methods=["POST"])
def lookup_breach():
    email = request.form.get("email", "").strip()
    if not email:
        flash("Please enter an email address.")
        return redirect(url_for("index"))

    breach_data = breach_check.check_email(email)
    risk = scoring.score_breach(breach_data)

    import json
    cache_result("email", email, json.dumps(breach_data), risk)

    return render_template("results.html", result_type="breach", result=breach_data, risk=risk)


@app.route("/lookup/ip", methods=["POST"])
def lookup_ip():
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("Please enter an IP address.")
        return redirect(url_for("index"))

    shodan_data = ip_intel.get_shodan_info(ip)
    abuse_data = ip_intel.get_abuseipdb_info(ip)

    result = {"ip": ip, "shodan": shodan_data, "abuseipdb": abuse_data}
    risk = scoring.score_ip(result)

    import json
    cache_result("ip", ip, json.dumps(result), risk)

    return render_template("results.html", result_type="ip", result=result, risk=risk)


@app.route("/lookup/metadata", methods=["POST"])
def lookup_metadata():
    if "file" not in request.files:
        flash("Please upload a file.")
        return redirect(url_for("index"))

    file = request.files["file"]
    if file.filename == "" or not allowed_file(file.filename):
        flash("Unsupported or missing file.")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    file.save(filepath)

    meta = metadata_extract.extract_metadata(filepath)
    risk = scoring.score_metadata(meta)

    # Clean up uploaded file after analysis
    try:
        os.remove(filepath)
    except OSError:
        pass

    return render_template("results.html", result_type="metadata", result=meta, risk=risk)


@app.route("/history")
def history():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT target_type, target_value, risk_score, created_at FROM lookups "
        "ORDER BY created_at DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return render_template("history.html", rows=rows)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)