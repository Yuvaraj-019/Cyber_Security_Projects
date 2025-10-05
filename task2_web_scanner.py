# task2_advanced_web_scanner.py
# Advanced Web Vulnerability Scanner: Tests SQLi, XSS, CSRF. Shows process and results in console.
# Educational use only. No file reports generated. Inspired by Wapiti and OWASP ZAP features.
# Tested on http://testphp.vulnweb.com for demo.

import requests
from bs4 import BeautifulSoup
import urllib.parse
import argparse
import json
import datetime
import time
from tqdm import tqdm
import os

# Expanded payloads
SQLI_PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 -- ", "1' OR '1'='1'#", "; --", "'; DROP TABLE users; --",
                 "1; WAITFOR DELAY '0:0:5'--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"'><script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>", "<body onload=alert(1)>", "javascript:alert(1)"]

# Security headers to check (commented out for focused demo on SQLi/XSS/CSRF)
# SEC_HEADERS = {
#     'Content-Security-Policy': 'Missing CSP - Allows inline scripts/styles',
#     'X-Frame-Options': 'Missing XFO - Clickjacking risk',
#     'X-Content-Type-Options': 'Missing XCTO - MIME sniffing risk',
#     'Strict-Transport-Security': 'Missing HSTS - Man-in-the-middle risk'
# }

# Severity mapping (focused on key vulns)
SEVERITY = {
    'SQLi': 'High',
    'XSS': 'Medium',
    'No CSRF': 'Medium'
    # 'Missing Header': 'Low'
}

# Remediation advice
REMEDIATION = {
    'SQLi': [
        "Use prepared statements or parameterized queries in your database code.",
        "Validate and sanitize all user inputs before processing.",
        "Implement an ORM (e.g., SQLAlchemy) to avoid raw SQL where possible.",
        "Enable database error logging without exposing details to users."
    ],
    'XSS': [
        "Escape all user-generated content using HTML entities (e.g., html.escape in Python).",
        "Implement Content Security Policy (CSP) headers to restrict script execution.",
        "Use libraries like bleach for sanitizing HTML output.",
        "Validate input types and lengths on both client and server sides."
    ],
    'No CSRF': [
        "Add CSRF tokens to all forms and verify them on the server.",
        "Use frameworks like Flask-WTF or Django's built-in CSRF protection.",
        "Include the token in HTTP headers for AJAX requests.",
        "Regenerate tokens on login/logout to prevent fixation attacks."
    ]
}


def fetch_links_and_forms(url):
    """Fetch links and forms from URL."""
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return [], []
    soup = BeautifulSoup(r.text, "html.parser")
    links = set(urllib.parse.urljoin(url, a["href"]) for a in soup.find_all("a", href=True))
    forms = []
    for form in soup.find_all("form"):
        action = urllib.parse.urljoin(url, form.get("action", ""))
        method = form.get("method", "get").lower()
        inputs = {inp.get("name"): inp.get("value", "") for inp in form.find_all("input") if inp.get("name")}
        csrf_token = any(
            inp.get("name") in ["csrf_token", "_token", "authenticity_token"] for inp in form.find_all("input"))
        forms.append({"action": action, "method": method, "inputs": inputs, "has_csrf": csrf_token})
    return list(links), forms


def test_sqli(url_or_action, is_post=False, form_data=None):
    """Test for SQL Injection. Returns findings list."""
    findings = []
    if is_post:
        for param in form_data:
            for p in SQLI_PAYLOADS:
                injected = form_data.copy()
                injected[param] = p
                try:
                    start = time.time()
                    r = requests.post(url_or_action, data=injected, timeout=6)
                    elapsed = time.time() - start
                    if any(kw in r.text.lower() for kw in ["sql syntax", "mysql", "syntax error", "sqlstate",
                                                           "ora-"]) or elapsed > 4:  # Time-based blind
                        finding = {"type": "SQLi", "location": url_or_action, "param": param, "payload": p,
                                   "response": r.text[:200]}
                        findings.append(finding)
                        print(
                            f"  - Testing SQLi on {url_or_action}... [!] Possible SQLi detected at {url_or_action} (payload: {p}) - Response snippet: {r.text[:100]}...")
                except:
                    continue
    else:
        parsed = urllib.parse.urlparse(url_or_action)
        qs = urllib.parse.parse_qs(parsed.query)
        if not qs:
            return findings
        for param in qs:
            for p in SQLI_PAYLOADS:
                injected = qs.copy()
                injected[param] = [p]
                new_qs = urllib.parse.urlencode(injected, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    r = requests.get(test_url, timeout=6)
                    if any(kw in r.text.lower() for kw in ["sql syntax", "mysql", "syntax error", "sqlstate", "ora-"]):
                        finding = {"type": "SQLi", "location": test_url, "param": param, "payload": p,
                                   "response": r.text[:200]}
                        findings.append(finding)
                        print(
                            f"  - Testing SQLi on {url_or_action}... [!] Possible SQLi detected at {test_url} (payload: {p}) - Response snippet: {r.text[:100]}...")
                except:
                    continue
    return findings


def test_xss(url_or_action, is_post=False, form_data=None):
    """Test for Reflected XSS. Returns findings list."""
    findings = []
    if is_post:
        for param in form_data:
            for p in XSS_PAYLOADS:
                injected = form_data.copy()
                injected[param] = p
                try:
                    r = requests.post(url_or_action, data=injected, timeout=6)
                    if any(payload in r.text for payload in XSS_PAYLOADS):
                        finding = {"type": "XSS", "location": url_or_action, "param": param, "payload": p,
                                   "response": r.text[:200]}
                        findings.append(finding)
                        print(f"  - Testing XSS on POST {url_or_action}... [!] Possible XSS in form with payload: {p}")
                except:
                    continue
    else:
        parsed = urllib.parse.urlparse(url_or_action)
        qs = urllib.parse.parse_qs(parsed.query)
        if not qs:
            for p in XSS_PAYLOADS:
                test_url = url_or_action + "?test=" + urllib.parse.quote(p)
                try:
                    r = requests.get(test_url, timeout=6)
                    if p in r.text:
                        finding = {"type": "XSS", "location": test_url, "param": "test", "payload": p,
                                   "response": r.text[:200]}
                        findings.append(finding)
                        print(
                            f"  - Testing XSS on {url_or_action}... [!] Possible Reflected XSS at {test_url} (payload: {p})")
                except:
                    continue
            return findings
        for param in qs:
            for p in XSS_PAYLOADS:
                injected = qs.copy()
                injected[param] = [p]
                new_qs = urllib.parse.urlencode(injected, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    r = requests.get(test_url, timeout=6)
                    if p in r.text:
                        finding = {"type": "XSS", "location": test_url, "param": param, "payload": p,
                                   "response": r.text[:200]}
                        findings.append(finding)
                        print(
                            f"  - Testing XSS on {url_or_action}... [!] Possible Reflected XSS at {test_url} (payload: {p})")
                except:
                    continue
    return findings


# def check_headers(url):
#     """Check for missing security headers. (Disabled for focused demo)"""
#     return []

def check_csrf(forms):
    """Check forms for CSRF tokens. Returns findings list."""
    findings = []
    for form in forms:
        if not form["has_csrf"]:
            finding = {"type": "No CSRF", "location": form["action"],
                       "description": "Form lacks CSRF protection token."}
            findings.append(finding)
            print(f"  - CSRF Check: [!] No CSRF token in form at {form['action']} (lacks protection)")
    return findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner (Console Output)")
    parser.add_argument("url", help="Target URL (e.g., http://testphp.vulnweb.com)")
    args = parser.parse_args()
    start_url = args.url
    start_time = time.time()

    print("Initiating advanced scan...")
    print("Finding links and forms...")
    all_findings = []
    links, forms = fetch_links_and_forms(start_url)
    scan_urls = [start_url] + links[:50]  # Limit for thoroughness

    # Scan links for SQLi, XSS
    print("Scanning URLs:")
    for url in tqdm(scan_urls, desc="Scanning URLs"):
        all_findings.extend(test_sqli(url))
        all_findings.extend(test_xss(url))
        # all_findings.extend(check_headers(url))  # Disabled for demo focus

    # Scan forms for SQLi, XSS, CSRF
    print("Scanning Forms:")
    for form in tqdm(forms, desc="Scanning Forms"):
        if form["method"] == "post":
            all_findings.extend(test_sqli(form["action"], is_post=True, form_data=form["inputs"]))
            all_findings.extend(test_xss(form["action"], is_post=True, form_data=form["inputs"]))
    all_findings.extend(check_csrf(forms))

    # Deduplicate findings
    unique_findings = []
    seen = set()
    for f in all_findings:
        key = (f["type"], f["location"], f.get("payload", ""))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Print summary based on key vuln types (SQLi, XSS, No CSRF)
    sqli_count = sum(1 for f in unique_findings if f["type"] == "SQLi")
    xss_count = sum(1 for f in unique_findings if f["type"] == "XSS")
    csrf_count = sum(1 for f in unique_findings if f["type"] == "No CSRF")
    total = sqli_count + xss_count + csrf_count

    print(f"\nTotal Vulnerabilities: {total}")
    high_count = sqli_count
    medium_count = xss_count + csrf_count
    if high_count > 0:
        print(f"High: {high_count} (SQLi)")
    if medium_count > 0:
        print(f"Medium: {medium_count} (XSS, No CSRF)")

    duration = time.time() - start_time
    print(f"\n[+] Scan complete. Target: {start_url} | Duration: {duration:.2f}s")

    if unique_findings:
        print(f"\n[!] {len(unique_findings)} unique vulnerabilities found. Check details above.")
    else:
        print("\n[+] No vulnerabilities detected.")

    # Add remediation section
    if unique_findings:
        print("\n" + "="*60)
        print("HOW TO FIX THESE VULNERABILITIES")
        print("="*60)
        vuln_types_found = set(f["type"] for f in unique_findings)
        for vuln_type in sorted(vuln_types_found):
            print(f"\n{vuln_type} ({SEVERITY.get(vuln_type, 'Unknown')} Severity):")
            print("-" * 40)
            for fix in REMEDIATION.get(vuln_type, ["Consult OWASP guidelines for remediation."]):
                print(f"  • {fix}")
            print()