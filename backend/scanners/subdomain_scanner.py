import requests


class SubdomainScanner:
    def scan(self, domain):
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"

            response = requests.get(
                url,
                timeout=20,
                headers={
                    "User-Agent": "CyberGuard"
                }
            )

            data = response.json()

            subdomains = set()

            for item in data:
                name = item.get("name_value", "")

                for sub in name.split("\n"):
                    sub = sub.strip()

                    if (
                        sub
                        and "*" not in sub
                        and sub.endswith(domain)
                    ):
                        subdomains.add(sub)

            return {
                "status": "ok",
                "domain": domain,
                "count": len(subdomains),
                "subdomains": sorted(subdomains)
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
