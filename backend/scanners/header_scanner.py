from .base import ScannerBase


class HeaderScanner:

    def scan(self, domain: str):
        url = f"https://{domain}"
        response = ScannerBase.safe_request(url)

        result = {
            "missing": [],
            "present": {},
            "risk": "low"
        }

        if not response:
            result["risk"] = "high"
            return result

        headers = response.headers

        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

        missing = []

        for h in security_headers:
            if h in headers:
                result["present"][h] = headers[h]
            else:
                missing.append(h)

        result["missing"] = missing

        # Risk calculation
        if len(missing) >= 4:
            result["risk"] = "high"
        elif len(missing) >= 2:
            result["risk"] = "medium"
        else:
            result["risk"] = "low"

        return result