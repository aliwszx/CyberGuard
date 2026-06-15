import ssl
import socket
from datetime import datetime


class SSLScanner:

    def scan(self, domain: str):
        context = ssl.create_default_context()

        result = {
            "ssl_status": "unknown",
            "issuer": None,
            "expires": None,
            "tls_version": None,
            "valid": False
        }

        try:
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:

                    cert = ssock.getpeercert()

                    result["issuer"] = dict(x[0] for x in cert["issuer"])
                    result["expires"] = cert["notAfter"]
                    result["tls_version"] = ssock.version()
                    result["valid"] = True
                    result["ssl_status"] = "valid"

        except Exception:
            result["ssl_status"] = "invalid"
            result["valid"] = False

        return result