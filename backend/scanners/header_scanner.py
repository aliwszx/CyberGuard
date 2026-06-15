import requests


class HeaderScanner:
    def scan(self, domain):
        try:
            url = f"https://{domain}"

            response = requests.get(
                url,
                timeout=15,
                allow_redirects=True,
                headers={
                    "User-Agent": "CyberGuard"
                }
            )

            headers = response.headers

            security_headers = {
                "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
                "Content-Security-Policy": headers.get("Content-Security-Policy"),
                "X-Frame-Options": headers.get("X-Frame-Options"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
                "Referrer-Policy": headers.get("Referrer-Policy"),
                "Permissions-Policy": headers.get("Permissions-Policy"),
            }

            present = {}
            missing = []

            for header, value in security_headers.items():
                if value:
                    present[header] = value
                else:
                    missing.append(header)

            if len(missing) >= 4:
                risk = "high"
            elif len(missing) >= 2:
                risk = "medium"
            else:
                risk = "low"

            return {
                "status": "ok",
                "domain": domain,
                "risk": risk,
                "present": present,
                "missing": missing
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
