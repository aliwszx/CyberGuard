import dns.resolver


class DNSScanner:
    def scan(self, domain):
        try:
            result = {}

            records = ["A", "AAAA", "MX", "NS", "TXT"]

            for record in records:
                try:
                    answers = dns.resolver.resolve(domain, record)

                    if record == "MX":
                        result[record] = [
                            str(r.exchange).rstrip(".")
                            for r in answers
                        ]
                    else:
                        result[record] = [
                            str(r)
                            for r in answers
                        ]

                except Exception:
                    result[record] = []

            return {
                "status": "ok",
                "domain": domain,
                "dns": result
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
