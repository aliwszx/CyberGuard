import socket


class IPScanner:
    def scan(self, target):
        try:
            ip = socket.gethostbyname(target)
            hostname = socket.gethostbyaddr(ip)[0]

            return {
                "ip": ip,
                "hostname": hostname,
                "status": "ok"
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }