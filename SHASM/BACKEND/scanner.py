"""Safe passive HTTP scanner: GET requests and response-header/cookie checks only."""
import ipaddress, re, socket
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlsplit, urlunsplit
import requests

USER_AGENT = "SHASM-SafeScanner/2.1"
TIMEOUT = (5, 12)
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 1_000_000
SENSITIVE_COOKIE = re.compile(r"(session|sess|auth|token|jwt|sid|login|identity|account)", re.I)

class ScanError(Exception):
    pass

def normalise_url(value):
    if not isinstance(value, str) or not value.strip():
        raise ScanError("Please provide a URL.")
    value = value.strip()
    if "://" not in value:
        value = "https://" + value
    p = urlsplit(value)
    if p.scheme.lower() not in ("http", "https") or not p.hostname:
        raise ScanError("Only valid HTTP and HTTPS URLs are supported.")
    if p.username or p.password:
        raise ScanError("URLs containing embedded credentials are not allowed.")
    try:
        if p.port is not None and not 1 <= p.port <= 65535:
            raise ScanError("Invalid port number.")
    except ValueError as exc:
        raise ScanError("Invalid port number.") from exc
    if any(ord(c) < 33 for c in p.netloc):
        raise ScanError("URL contains invalid whitespace or control characters.")
    return urlunsplit((p.scheme.lower(), p.netloc, p.path or "/", p.query, ""))

def validate_public(url):
    p = urlsplit(url)
    if not p.hostname:
        raise ScanError("Destination has no hostname.")
    try:
        addresses = [ipaddress.ip_address(p.hostname)]
    except ValueError:
        try:
            records = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80),
                                         type=socket.SOCK_STREAM)
            addresses = list({ipaddress.ip_address(x[4][0].split("%")[0]) for x in records})
        except socket.gaierror as exc:
            raise ScanError(f"Could not resolve hostname: {p.hostname}") from exc
    if not addresses or any(not a.is_global for a in addresses):
        raise ScanError("Blocked destination: host resolves to a non-public IP address.")

def cookie_headers(response):
    raw = getattr(response.raw, "headers", None)
    if raw is not None:
        for method_name in ("getlist", "get_all"):
            method = getattr(raw, method_name, None)
            if callable(method):
                values = method("Set-Cookie")
                if values:
                    return [str(v) for v in values]
    value = response.headers.get("Set-Cookie")
    return [value] if value else []

def parse_cookie(header):
    jar = SimpleCookie()
    try:
        jar.load(header)
    except Exception:
        return None, set()
    if not jar:
        return None, set()
    name = next(iter(jar))
    morsel = jar[name]
    attrs = set()
    for flag in ("secure", "httponly"):
        if re.search(rf"(?:^|;)\\s*{flag}\\s*(?:;|$)", header, re.I):
            attrs.add(flag)
    if re.search(r"(?:^|;)\\s*samesite\\s*=", header, re.I):
        attrs.add("samesite")
    for attr in ("domain", "path", "expires", "max-age"):
        if morsel[attr]:
            attrs.add(attr)
    return name, attrs

def add(findings, title, severity, confidence, evidence, remediation, category="Security Headers"):
    if not any(f["title"] == title and f["evidence"] == evidence for f in findings):
        findings.append({"title": title, "severity": severity, "confidence": confidence,
                         "category": category, "evidence": evidence, "remediation": remediation})

def inspect_cookies(response, findings):
    observed = []
    for header in cookie_headers(response):
        name, attrs = parse_cookie(header)
        if not name:
            observed.append({"name": None, "attributes": [], "parse_status": "unparsed"})
            continue
        observed.append({"name": name, "attributes": sorted(attrs), "parse_status": "parsed"})
        severity = "Medium" if SENSITIVE_COOKIE.search(name) else "Low"
        evidence = f"Set-Cookie name={name!r}; attributes={sorted(attrs)}"
        if "httponly" not in attrs:
            add(findings, "Cookie Missing HttpOnly", severity, "High", evidence + "; HttpOnly absent.",
                f"Set HttpOnly on {name} if client-side JavaScript does not need to read it.", "Cookie Security")
        if response.url.lower().startswith("https://") and "secure" not in attrs:
            add(findings, "Cookie Missing Secure Flag", severity, "High", evidence + "; Secure absent on HTTPS response.",
                f"Set Secure on {name} so browsers send it only over HTTPS.", "Cookie Security")
        if "samesite" not in attrs:
            add(findings, "Cookie Missing SameSite Attribute", "Low", "Medium", evidence + "; SameSite absent.",
                f"Choose an appropriate SameSite policy for {name}; use None only when cross-site use is required and pair it with Secure.",
                "Cookie Security")
    return observed

def inspect_headers(response, findings):
    h, observed = response.headers, []
    checks = [
        ("Content-Security-Policy", "Content Security Policy Missing", "Low",
         "Define and test a Content-Security-Policy appropriate for the application."),
        ("X-Content-Type-Options", "X-Content-Type-Options Missing", "Low",
         "Send X-Content-Type-Options: nosniff and use correct Content-Type values."),
        ("Referrer-Policy", "Referrer Policy Missing", "Info",
         "Set an intentional Referrer-Policy, commonly strict-origin-when-cross-origin."),
    ]
    for header, title, severity, remediation in checks:
        value = h.get(header)
        observed.append({"header": header, "present": bool(value), "value": value or ""})
        if not value:
            add(findings, title, severity, "High", f"{header} was absent on the final response.", remediation)
    hsts = h.get("Strict-Transport-Security")
    observed.append({"header": "Strict-Transport-Security", "present": bool(hsts), "value": hsts or ""})
    if response.url.lower().startswith("https://") and not hsts:
        add(findings, "HTTP Strict Transport Security Missing", "Low", "High",
            "Final response used HTTPS but Strict-Transport-Security was absent.",
            "After confirming HTTPS support, configure an appropriate HSTS max-age; carefully assess includeSubDomains and preload.")
    xfo, csp = h.get("X-Frame-Options"), h.get("Content-Security-Policy", "")
    frame_ancestors = bool(re.search(r"(?:^|;)\\s*frame-ancestors\\b", csp, re.I))
    observed.extend([{"header": "X-Frame-Options", "present": bool(xfo), "value": xfo or ""},
                     {"header": "CSP frame-ancestors", "present": frame_ancestors,
                      "value": "present" if frame_ancestors else ""}])
    if not xfo and not frame_ancestors:
        add(findings, "Clickjacking Protection Header Not Detected", "Low", "Medium",
            "Neither X-Frame-Options nor CSP frame-ancestors was detected.",
            "If framing is not required, configure CSP frame-ancestors and consider X-Frame-Options for legacy browser support.")
    server = h.get("Server")
    if server:
        observed.append({"header": "Server", "present": True, "value": server})
        if re.search(r"\\d+\\.\\d+", server):
            add(findings, "Server Version Disclosure", "Info", "Medium",
                f"Server response header disclosed {server!r}.",
                "Consider suppressing detailed server product/version information. This alone does not prove an exploitable vulnerability.")
    return observed

def perform_scan(target_url, safe_mode=True):
    started = datetime.now(timezone.utc).isoformat()
    findings, redirects, cookie_observations = [], [], []
    session, response = requests.Session(), None
    session.trust_env = False
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
    try:
        current = normalise_url(target_url)
        for hop in range(MAX_REDIRECTS + 1):
            validate_public(current)
            response = session.get(current, timeout=TIMEOUT, allow_redirects=False, verify=True, stream=True)
            redirects.append({"url": current, "status_code": response.status_code})
            cookie_observations.extend(inspect_cookies(response, findings))
            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                response.close()
                if not location:
                    raise ScanError("Redirect response did not include a Location header.")
                if hop == MAX_REDIRECTS:
                    raise ScanError(f"Redirect limit ({MAX_REDIRECTS}) exceeded.")
                current = normalise_url(urljoin(current, location))
                continue

            final_url, status_code = response.url, response.status_code
            content_type = response.headers.get("Content-Type", "")
            security_headers = inspect_headers(response, findings)
            body_bytes = 0
            try:
                for chunk in response.iter_content(chunk_size=16384):
                    if chunk:
                        body_bytes += len(chunk)
                        if body_bytes >= MAX_BODY_BYTES:
                            break
            finally:
                response.close()

            counts = {level: sum(f["severity"] == level for f in findings)
                      for level in ("Critical", "High", "Medium", "Low", "Info")}
            summary = ("No issues detected by the passive checks performed." if not findings
                       else "Potential security-hardening observations detected; review the evidence.")
            return {
                "target": target_url, "final_url": final_url, "status_code": status_code,
                "scanned_at": started, "scan_type": "safe_passive", "summary": summary,
                "finding_counts": counts, "findings": findings, "cookies": cookie_observations,
                "security_headers": security_headers,
                "page_observations": {"content_type": content_type,
                    "response_body_bytes_read": min(body_bytes, MAX_BODY_BYTES),
                    "response_body_limit_reached": body_bytes >= MAX_BODY_BYTES},
                "redirect_chain": redirects,
                "limitations": [
                    "Unauthenticated passive HTTP checks only; authenticated pages are not inspected.",
                    "JavaScript, forms, application logic and site-wide crawling are not tested.",
                    "Missing headers are hardening observations, not proof of exploitability.",
                    "Manually verify findings before treating them as confirmed vulnerabilities."
                ]
            }
        raise ScanError("No final HTTP response was received.")
    except requests.exceptions.SSLError:
        message = "TLS certificate verification failed; certificate validation was not disabled."
    except requests.exceptions.Timeout:
        message = "The target did not respond within the configured timeout."
    except requests.exceptions.RequestException as exc:
        message = f"HTTP request failed: {type(exc).__name__}: {exc}"
    except ScanError as exc:
        message = str(exc)
    except Exception as exc:
        message = f"Unexpected scanner error: {type(exc).__name__}: {exc}"
    finally:
        if response is not None:
            response.close()
        session.close()
    return {"target": target_url, "scanned_at": started, "error": message,
            "findings": [], "redirect_chain": redirects}
