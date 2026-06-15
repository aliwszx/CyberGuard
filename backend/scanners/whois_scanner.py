import whois

class WhoisScanner:
    def scan(self, domain):
        try:
            data = whois.whois(domain)

            creation_date = data.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            expiration_date = data.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]

            return {
                "domain": domain,
                "registrar": data.registrar,
                "creation_date": str(creation_date) if creation_date else "Unknown",
                "expiration_date": str(expiration_date) if expiration_date else "Unknown",
                "name_servers": data.name_servers or [],
                "status": "ok"
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
