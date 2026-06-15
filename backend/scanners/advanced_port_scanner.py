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

RISKY_PORTS = {21, 23, 445, 3306, 3389, 5432, 6379, 27017}

RISK_DESCRIPTIONS = {
    21:    ("FTP", "Şifrəsiz fayl ötürməsi — credential sniffing riski"),
    22:    ("SSH", "Brute-force hücumlarına məruz qala bilər"),
    23:    ("Telnet", "Şifrəsiz protokol — kritik risk"),
    25:    ("SMTP", "Spam relay potensialı"),
    80:    ("HTTP", "Şifrəsiz veb trafiki"),
    443:   ("HTTPS", "Standart TLS — adətən təhlükəsiz"),
    445:   ("SMB", "EternalBlue/ransomware hücum vektoru"),
    3306:  ("MySQL", "DB birbaşa açıqdır — çox riskli"),
    3389:  ("RDP", "Remote Desktop — brute-force & BlueKeep hədəfi"),
    5432:  ("PostgreSQL", "DB birbaşa açıqdır — riskli"),
    6379:  ("Redis", "Autentifikasiyasız giriş mümkündür"),
    27017: ("MongoDB", "Autentifikasiyasız açıq DB riski"),
}

RECOMMENDATIONS = {
    21:    "FTP əvəzinə SFTP/FTPS istifadə edin",
    22:    "SSH key-based auth aktivləşdirin, password auth bağlayın",
    23:    "Telnet-i tamamilə bağlayın, SSH istifadə edin",
    25:    "SMTP relay-i yalnız etibarlı IP-lərə icazə verin",
    80:    "HTTP-ni HTTPS-ə yönləndirin",
    443:   "TLS versiyasını və sertifikatı yoxlayın",
    445:   "SMB-ni internetdən tamamilə bağlayın",
    3306:  "MySQL-i yalnız localhost üçün açın (bind-address=127.0.0.1)",
    3389:  "RDP-ni VPN arxasına aparın, birbaşa bağlayın",
    5432:  "PostgreSQL-i firewall ilə qoruyun",
    6379:  "Redis-ə parol qoyun (requirepass) və bind edin",
    27017: "MongoDB auth aktivləşdirin, portun açıq olmasını bağlayın",
}


class AdvancedPortScanner:
    def __init__(self):
        self.risky_ports = RISKY_PORTS

    def parse_ports(self, port_spec=None, port_range=None):
        """
        port_spec: "80,443,8080" — xüsusi portlar
        port_range: "1-1000" — aralıq
        Heç biri verilməyibsə: standart COMMON_PORTS
        """
        if port_spec:
            result = set()
            for part in str(port_spec).split(","):
                part = part.strip()
                if "-" in part:
                    s, e = map(int, part.split("-", 1))
                    result.update(range(s, min(e + 1, 65536)))
                else:
                    result.add(int(part))
            return sorted(result)

        if port_range:
            parts = str(port_range).split("-")
            start = int(parts[0])
            end = int(parts[1]) if len(parts) > 1 else start
            return list(range(start, min(end + 1, 65536)))

        return sorted(COMMON_PORTS.keys())

    def detect_service(self, port):
        if port in COMMON_PORTS:
            return COMMON_PORTS[port]
        try:
            return socket.getservbyport(port)
        except Exception:
            return "Unknown"

    def grab_banner(self, sock, port):
        try:
            sock.settimeout(2)
            if port in [80, 8080]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            raw = sock.recv(512)
            return raw.decode("utf-8", errors="ignore").strip() or None
        except Exception:
            return None

    def _scan_port(self, ip, port, timeout=2.0):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = self.detect_service(port)
                banner = self.grab_banner(sock, port)
                sock.close()
                return {"port": port, "state": "open", "service": service, "banner": banner}
            sock.close()
            return {"port": port, "state": "closed"}
        except socket.timeout:
            return {"port": port, "state": "filtered"}
        except socket.gaierror:
            return {"port": port, "state": "error", "error": "hostname resolve failed"}
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

    def get_risk_analysis(self, open_ports):
        """Açıq portlar üçün risk analizi və tövsiyələr"""
        analyses = []
        for p in open_ports:
            port_num = p["port"]
            if port_num in RISK_DESCRIPTIONS:
                service, desc = RISK_DESCRIPTIONS[port_num]
                rec = RECOMMENDATIONS.get(port_num, "Portu firewall ilə qoruyun")
                analyses.append({
                    "port": port_num,
                    "service": service,
                    "risk_desc": desc,
                    "recommendation": rec,
                    "is_risky": port_num in RISKY_PORTS
                })
        return analyses

    def scan(
        self,
        domain: str,
        port_spec=None,
        port_range=None,
        speed="fast",
        show_all=False
    ) -> dict:
        """
        speed: "fast" (timeout=1s, 100 worker) | "deep" (timeout=3s, 30 worker)
        show_all: True = bütün portları qaytar, False = yalnız açıqları
        """
        clean_domain = ScannerBase.normalize_domain(domain)

        result = {
            "ip": None,
            "host_status": "down",
            "ports": [],
            "open_ports": [],
            "risk": "unknown",
            "risk_analysis": [],
            "error": None,
            "scan_mode": f"{'deep' if speed == 'deep' else 'fast'} scan",
        }

        ip = ScannerBase.get_ip(clean_domain)
        if not ip:
            result["error"] = f"'{clean_domain}' domeni üçün IP tapılmadı"
            return result

        result["ip"] = ip
        result["host_status"] = "up"

        ports = self.parse_ports(port_spec=port_spec, port_range=port_range)
        result["total_scanned"] = len(ports)

        timeout = 1.0 if speed == "fast" else 3.0
        workers = 100 if speed == "fast" else 30

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._scan_port, ip, port, timeout): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    scan_result = future.result(timeout=10)
                except Exception:
                    port = futures[future]
                    scan_result = {"port": port, "state": "error"}

                if show_all:
                    result["ports"].append(scan_result)
                if scan_result["state"] == "open":
                    result["open_ports"].append(scan_result)

        result["ports"].sort(key=lambda x: x["port"])
        result["open_ports"].sort(key=lambda x: x["port"])
        result["risk"] = self.calculate_risk(result["open_ports"])
        result["risk_analysis"] = self.get_risk_analysis(result["open_ports"])

        return result
