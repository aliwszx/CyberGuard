import asyncio
from scanners.dns_scanner import DNSScanner
from scanners.ssl_scanner import SSLScanner
from scanners.header_scanner import HeaderScanner
from scanners.tech_detector import TechDetector
from scanners.port_scanner import PortScanner


class ScannerService:

    def __init__(self):
        self.dns = DNSScanner()
        self.ssl = SSLScanner()
        self.headers = HeaderScanner()
        self.tech = TechDetector()
        self.ports = PortScanner()

    def full_scan(self, domain: str) -> dict:
        """Sinxron (FastAPI endpoint-lər üçün)"""
        return {
            "domain": domain,
            "dns": self.dns.scan(domain),
            "ssl": self.ssl.scan(domain),
            "headers": self.headers.scan(domain),
            "technology": self.tech.scan(domain),
            "ports": self.ports.scan(domain)
        }

    async def full_scan_async(self, domain: str) -> dict:
        """
        Asinxron wrapper — Telegram bot handler-ləri üçün.
        Sinxron scan-ı thread pool-da işlədir ki, event loop bloklanmasın.
        """
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self.full_scan, domain)
        return result
