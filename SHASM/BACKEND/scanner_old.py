import requests
from bs4 import BeautifulSoup

def perform_scan(target_url, safe_mode=True):
    findings = []
    print(f"\n[+] STARTING SCAN: {target_url}")
    
    try:
        # Use a session to persist cookies across redirects
        session = requests.Session()
        session.headers.update({'User-Agent': 'SHASM-Scanner/1.0'})
        
        response = session.get(target_url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # --- DEBUG LOGS ---
        print(f"[i] Final URL: {response.url}")
        print(f"[i] Status Code: {response.status_code}")

        # --- METHOD 1: Check Cookies in the "Jar" (History) ---
        # This finds cookies even if they were set on a redirect page
        all_cookies = session.cookies
        
        if len(all_cookies) > 0:
            for cookie in all_cookies:
                print(f"[i] Found Cookie: {cookie.name} = {cookie.value}")
                
                # Check for HttpOnly (Tricky in Python, we check standard attributes)
                # Note: 'HttpOnly' is often a non-standard attribute in Python's cookiejar
                is_httponly = False
                if cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly'):
                    is_httponly = True
                
                # Check Secure
                is_secure = cookie.secure

                if not is_httponly:
                    print(f"[!] VULNERABILITY: Cookie {cookie.name} is missing HttpOnly")
                    findings.append({
                        "title": "Cookie Missing HttpOnly",
                        "severity": "High",
                        "evidence": f"Cookie: {cookie.name}",
                        "remediation": f"Set the HttpOnly flag for the {cookie.name} cookie."
                    })
                
                if not is_secure and "https" in target_url:
                    print(f"[!] WARNING: Cookie {cookie.name} is missing Secure flag")
                    findings.append({
                        "title": "Cookie Missing Secure Flag",
                        "severity": "Medium",
                        "evidence": f"Cookie: {cookie.name}",
                        "remediation": "Set the Secure flag for this cookie."
                    })

        else:
            print("[-] No cookies found in the session jar.")
            findings.append({
                "title": "No Cookies Detected",
                "severity": "Info",
                "evidence": "N/A",
                "remediation": "No session cookies were set during the scan chain."
            })

        # --- CHECK: Forms/Inputs ---
        forms = soup.find_all('form')
        if forms:
            print(f"[i] Found {len(forms)} forms.")
            findings.append({
                "title": "Input Forms Detected",
                "severity": "Info",
                "evidence": f"Found {len(forms)} forms.",
                "remediation": "Ensure inputs are sanitized."
            })

    except Exception as e:
        print(f"[!] ERROR: {e}")
        return {"error": str(e), "findings": []}

    print("[+] SCAN COMPLETE\n")
    return {"findings": findings}