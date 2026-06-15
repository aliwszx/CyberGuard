import socket
import concurrent.futures
from .base import ScannerBase

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


class PortScanner:
    def __init__(self):
        self.risky_ports = {
            21, 23, 445, 3306, 3389, 5432, 6379, 27017
        }

    def parse_ports(self, ports=None):
        if ports is None:
            return sorted(COMMON_PORTS.keys())

        if isinstance(ports, list):
            return sorted(ports)

        result = set()
        for part in str(ports).split(","):
            part = part.strip()
            if "-" in part:
                start, end = map(int, part.split("-"))
                result.update(range(start, end + 1))
            else:
                result.add(int(part))

        return sorted(result)

    def detect_service(self, port):
        # Əvvəlcə öz siyahımıza baxırıq, sonra sisteme
        if port in COMMON_PORTS:
            return COMMON_PORTS[port]
        try:
            return socket.getservbyport(port)
        except Exception:
            return "Unknown"

    def grab_banner(self, sock, port):
        banner = None
        try:
            sock.settimeout(2)
            if port in [80, 8080]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 22:
                pass  # SSH banner avtomatik göndərir
            raw = sock.recv(512)
            banner = raw.decode("utf-8", errors="ignore").strip()
        except Exception:
            pass
        return banner if banner else None

    def _scan_port(self, ip, port, timeout=2.0):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            result = sock.connect_ex((ip, port))

            if result == 0:
                service = self.detect_service(port)
                banner = self.grab_banner(sock, port)
                sock.close()
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner
                }

            sock.close()
            return {"port": port, "state": "closed"}

        except socket.timeout:
            return {"port": port, "state": "filtered"}
        except socket.gaierror:
            return {"port": port, "state": "error", "error": "hostname resolve failed"}
        except OSError as e:
            return {"port": port, "state": "error", "error": str(e)}
        except Exception as e:
            return {"port": port, "state": "error", "error": str(e)}

    def calculate_risk(self, open_ports):
        port_nums = {p["port"] for p in open_ports}

        if self.risky_ports & port_nums:
            return "high"
        if len(open_ports) > 5:
            return "medium"
        if len(open_ports) > 0:
            return "low"
        return "minimal"

    def scan(self, domain: str) -> dict:
        # Domain-i normalize edirik (http:// və ya path ola bilər)
        clean_domain = ScannerBase.normalize_domain(domain)

        result = {
            "ip": None,
            "host_status": "down",
            "ports": [],
            "open_ports": [],
            "risk": "unknown",
            "error": None
        }

        # IP resolve
        ip = ScannerBase.get_ip(clean_domain)
        if not ip:
            result["error"] = f"'{clean_domain}' domeni üçün IP tapılmadı"
            return result

        result["ip"] = ip
        result["host_status"] = "up"

        ports = self.parse_ports()

        # max_workers-i azaldırıq — 200 thread çox agresivdir, firewall bloklaya bilər
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(self._scan_port, ip, port, 2.0): port
                for port in ports
            }

            for future in concurrent.futures.as_completed(futures):
                try:
                    scan_result = future.result(timeout=5)
                except Exception:
                    port = futures[future]
                    scan_result = {"port": port, "state": "error"}

                result["ports"].append(scan_result)
                if scan_result["state"] == "open":
                    result["open_ports"].append(scan_result)

        result["ports"].sort(key=lambda x: x["port"])
        result["open_ports"].sort(key=lambda x: x["port"])
        result["risk"] = self.calculate_risk(result["open_ports"])

        return result
