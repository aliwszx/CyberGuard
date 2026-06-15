from .base import ScannerBase


class TechDetector:

    def scan(self, domain: str):
        url = f"https://{domain}"
        response = ScannerBase.safe_request(url)

        result = {
            "server": None,
            "framework": None,
            "cms": None,
            "cdn": None
        }

        if not response:
            return result

        headers = response.headers
        html = response.text.lower()

        # Server detection
        result["server"] = headers.get("Server")

        # CDN detection
        if "cloudflare" in headers.get("Server", "").lower():
            result["cdn"] = "Cloudflare"

        # Framework detection (basic heuristics)
        if "react" in html:
            result["framework"] = "React"
        elif "vue" in html:
            result["framework"] = "Vue"
        elif "angular" in html:
            result["framework"] = "Angular"

        # CMS detection
        if "wp-content" in html:
            result["cms"] = "WordPress"

        return result