import logging
import whois

logger = logging.getLogger(__name__)

class WhoisScanner:
    def scan(self, domain):
        try:
            data = whois.whois(domain)

            logger.info(f"WHOIS RESULT: {data}")

            return {
                "domain": domain,
                "registrar": data.registrar,
                "creation_date": str(data.creation_date),
                "expiration_date": str(data.expiration_date),
                "name_servers": data.name_servers,
                "status": "ok"
            }

        except Exception as e:
            logger.exception("WHOIS ERROR")
            return {
                "status": "error",
                "error": str(e)
            }
