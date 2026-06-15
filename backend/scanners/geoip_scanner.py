import socket
import requests


class GeoIPScanner:
    def scan(self, target):
        try:
            try:
                ip = socket.gethostbyname(target)
            except Exception:
                ip = target

            r = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=10
            )

            data = r.json()

            if data.get("status") != "success":
                return {
                    "status": "error",
                    "error": "GeoIP məlumatı tapılmadı"
                }

            return {
                "status": "ok",
                "ip": ip,
                "country": data.get("country"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "asn": data.get("as"),
                "timezone": data.get("timezone")
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
