import socket
import requests
from urllib.parse import urlparse


class ScannerBase:

    @staticmethod
    def normalize_domain(domain: str) -> str:
        domain = domain.strip().lower()
        domain = domain.replace("http://", "").replace("https://", "")
        return domain.split("/")[0]

    @staticmethod
    def get_ip(domain: str) -> str | None:
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    @staticmethod
    def safe_request(url: str):
        try:
            headers = {
                "User-Agent": "CyberGuard-Security-Bot/1.0"
            }
            return requests.get(url, timeout=5, headers=headers)
        except Exception:
            return None