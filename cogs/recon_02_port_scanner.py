#!/usr/bin/env python3
"""
Maxima Cog: Quick Port Scanner — Hızlı TCP Tarama
Yaygın portları (top-100) hızlıca tarar, servis adı ve risk seviyesi belirler.
Recon_35 (AsyncPortScanner) tam 1000 portluk async tarama yapar;
bu modül daha hızlı ve hafif bir alternatif sunar.

Özellikler:
  - Top-100 yaygın port taraması (sync, thread-pool paralel)
  - Servis adı tespiti (well-known ports)
  - Basit banner grab (ilk 256 byte)
  - Risk sınıflandırması (critical/high/medium/low)
  - Toplu sonuç özeti
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from utils.base_module import BaseModule, ModuleResult


# ── Top-100 yaygın port listesi ────────────────────────────────
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 119, 135, 137, 139,
    143, 161, 179, 389, 443, 445, 465, 514, 515, 548, 554, 587,
    631, 636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723, 1900,
    2049, 2375, 3000, 3128, 3306, 3389, 4443, 4848, 5000, 5060,
    5432, 5631, 5800, 5900, 5984, 5985, 6379, 6443, 7001, 7070,
    7474, 8000, 8001, 8008, 8009, 8080, 8081, 8088, 8161, 8443,
    8529, 8888, 8983, 9000, 9090, 9200, 9300, 9418, 9443, 10000,
    10250, 11211, 27017, 27018, 50000, 61616,
]

# ── Servis adları ───────────────────────────────────────────────
SERVICE_NAMES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 81: "HTTP-Alt", 88: "Kerberos", 110: "POP3",
    111: "RPC", 119: "NNTP", 135: "MSRPC", 137: "NetBIOS",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "Printer", 548: "AFP", 554: "RTSP",
    587: "SMTP-Sub", 631: "IPP", 636: "LDAPS", 873: "Rsync",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 1900: "SSDP",
    2049: "NFS", 2375: "Docker", 3000: "Dev-HTTP", 3128: "Proxy",
    3306: "MySQL", 3389: "RDP", 4443: "HTTPS-Alt", 4848: "GlassFish",
    5000: "Dev-HTTP", 5060: "SIP", 5432: "PostgreSQL", 5631: "pcAnywhere",
    5800: "VNC-HTTP", 5900: "VNC", 5984: "CouchDB", 5985: "WinRM",
    6379: "Redis", 6443: "K8s-API", 7001: "WebLogic", 7070: "RealServer",
    7474: "Neo4j", 8000: "HTTP-Alt", 8001: "HTTP-Alt", 8008: "HTTP-Alt",
    8009: "AJP", 8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8088: "HTTP-Alt",
    8161: "ActiveMQ", 8443: "HTTPS-Alt", 8529: "ArangoDB",
    8888: "HTTP-Alt", 8983: "Solr", 9000: "HTTP-Alt", 9090: "Prometheus",
    9200: "Elasticsearch", 9300: "ES-Transport", 9418: "Git",
    9443: "HTTPS-Alt", 10000: "Webmin", 10250: "K8s-Kubelet",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB-Alt",
    50000: "SAP", 61616: "ActiveMQ",
}

# ── Risk sınıflandırması ────────────────────────────────────────
CRITICAL_PORTS: Set[int] = {2375, 6443, 10250, 9200, 9300, 27017, 6379, 11211, 5984, 50000, 61616}
HIGH_PORTS: Set[int] = {23, 445, 139, 3389, 5900, 3306, 5432, 1433, 7001, 8888, 1521, 4848, 8161, 9090}
MEDIUM_PORTS: Set[int] = {21, 25, 110, 143, 1080, 3128, 8080, 1723, 5060, 873}


class PortScanner(BaseModule):
    """Quick Port Scanner — Hızlı top-100 TCP tarama"""

    def run(self) -> ModuleResult:
        self.log("Hızlı port taraması başlatılıyor (top-100 TCP)...")

        ip = self.resolve_ip()
        if not ip:
            self.add_finding("IP Çözümlenemedi",
                             f"Hedef: {self.host} — DNS çözümleme başarısız", "medium")
            return self.results

        self.results["summary"]["IP"] = ip
        self.results["summary"]["Hostname"] = self.host
        self.log(f"Hedef: {self.host} ({ip})", "success")

        # ── Thread-pool ile paralel tarama ──
        open_ports: List[Tuple[int, str, str]] = []  # (port, service, banner)
        timeout = max(0.5, min(self.timeout * 0.15, 2.0))

        with ThreadPoolExecutor(max_workers=30) as pool:
            futures = {
                pool.submit(self._check_port, ip, port, timeout): port
                for port in TOP_100_PORTS
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        open_ports.sort(key=lambda x: x[0])

        # ── Bulgular ──
        for port, service, banner in open_ports:
            if port in CRITICAL_PORTS:
                risk = "critical"
            elif port in HIGH_PORTS:
                risk = "high"
            elif port in MEDIUM_PORTS:
                risk = "medium"
            else:
                risk = "low"

            detail = f"Port {port}/{service}"
            if banner:
                detail += f" | Banner: {banner[:80]}"
            self.add_finding(f"Açık Port: {port}/{service}", detail, risk)

        # ── Özet ──
        self.results["summary"]["Taranan Port"] = len(TOP_100_PORTS)
        self.results["summary"]["Açık Port"] = len(open_ports)
        self.results["summary"]["Açık Liste"] = ", ".join(
            f"{p}/{s}" for p, s, _ in open_ports
        )

        if not open_ports:
            self.add_finding("Açık Port Bulunamadı",
                             f"{len(TOP_100_PORTS)} yaygın port tarandı — hiçbiri erişilebilir değil",
                             "info")

        self.log(f"Tarama tamamlandı: {len(open_ports)} açık port", "success")
        return self.results

    def _check_port(self, ip: str, port: int, timeout: float
                    ) -> Optional[Tuple[int, str, str]]:
        """Tek port kontrolü + banner grab."""
        service = SERVICE_NAMES.get(port, f"port-{port}")
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                banner = self._grab_banner(s, port)
                return (port, service, banner)
        except Exception:
            pass
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        return None

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Basit banner grab — ilk 256 byte."""
        try:
            # HTTP portları için probe gönder
            if port in (80, 81, 8000, 8001, 8008, 8080, 8081, 8088, 8888, 443, 8443):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            sock.settimeout(1.0)
            data = sock.recv(256)
            return data.decode("utf-8", errors="replace").strip()[:100]
        except Exception:
            return ""


__all__ = ["PortScanner"]
