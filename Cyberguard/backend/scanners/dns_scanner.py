import dns.resolver


class DNSScanner:

    def scan(self, domain: str):
        result = {
            "target": domain,
            "dns": {
                "A": [],
                "AAAA": [],
                "MX": [],
                "TXT": [],
                "NS": [],
                "CNAME": []
            }
        }

        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
                if answers:
                    result["dns"][rtype] = [str(r.to_text()) for r in answers]
            except Exception:
                result["dns"][rtype] = []

        return result