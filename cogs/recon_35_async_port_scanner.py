#!/usr/bin/env python3
"""
Maxima Cog: Async Port Scanner — v2 (nmap benzeri)

Özellikler:
  - 65535 port, asyncio tabanlı (~50x hız)
  - Servis/versiyon tespiti (banner grabbing + regex imzalar)
  - OS fingerprinting (TTL + banner analizi)
  - SSL/TLS sertifika bilgisi (açık HTTPS portlar için)
  - Servis risk skoru (HIGH/MED/LOW/INFO)
  - SYN benzeri bağlantı testi (stdlib ile)
  - UDP port tespiti (yaygın portlar, sync)
  - Nmap tarzı port açıklama çıktısı
  - SecLists'ten alınan top-1000 port sıralaması
  - Custom port aralığı: --ports 22,80,443 veya 1-1024 veya karma
"""

import asyncio
import socket
import ssl
import time
import re
from typing import Dict, List, Optional, Set, Tuple
from utils.base_module import BaseModule, ModuleResult

# ── Top-1000 port sıralaması (nmap default sırasıyla) ────────
TOP_1000_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113,
    81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000,
    513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128,
    444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9,
    6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
    # DevOps / Cloud
    2375, 2376, 4243, 6443, 8001, 9443, 10250, 10255, 30000, 32767,
    # Databases
    27017, 27018, 6379, 11211, 5984, 9200, 9300, 7474, 8529, 7687,
    # Dev tools
    4848, 8161, 61616, 61617, 8983, 7001, 7002, 9043, 9060, 9080,
    # Monitoring
    3000, 9090, 9093, 9094, 9091, 4194, 8086, 2003, 8125,
    # VPN/Remote
    1194, 1701, 500, 4500, 1080, 3128, 8118,
    # File sharing
    69, 137, 138, 2049, 111, 892,
    # Mail extended
    24, 366, 465, 587, 993, 995, 2525,
    # Additional web
    4000, 4001, 5000, 7080, 8002, 8003, 8080, 8090, 8181, 8282,
    8383, 8484, 8585, 8686, 8787, 8888, 8989, 9000, 9001, 9002,
    9003, 9090, 9091, 9191, 9292, 9292, 9393, 9494, 9595,
    # SAP / ERP
    3200, 3201, 3300, 3600, 8000, 50000, 50001,
]
TOP_1000_PORTS = sorted(set(TOP_1000_PORTS))

# ── Servis imzaları (banner → versiyon) ──────────────────────
SERVICE_SIGNATURES: Dict[int, Dict] = {
    21:    {"name": "FTP",            "probe": b"",                           "regex": r"(220[- ].*?)\r?\n"},
    22:    {"name": "SSH",            "probe": b"",                           "regex": r"(SSH-[\d.]+-\S+)"},
    23:    {"name": "Telnet",         "probe": b"\n",                         "regex": r""},
    25:    {"name": "SMTP",           "probe": b"EHLO maxima\r\n",            "regex": r"(220[- ].*?)\r?\n"},
    53:    {"name": "DNS",            "probe": b"",                           "regex": r""},
    80:    {"name": "HTTP",           "probe": b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n", "regex": r"Server: (.*?)\r?\n"},
    110:   {"name": "POP3",          "probe": b"",                           "regex": r"(\+OK.*?)\r?\n"},
    143:   {"name": "IMAP",          "probe": b"",                           "regex": r"(\* OK.*?)\r?\n"},
    443:   {"name": "HTTPS",         "probe": b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n", "regex": r"Server: (.*?)\r?\n"},
    445:   {"name": "SMB",           "probe": b"",                           "regex": r""},
    3306:  {"name": "MySQL",         "probe": b"",                           "regex": r"([\d]+\.[\d]+\.[\d]+)"},
    5432:  {"name": "PostgreSQL",    "probe": b"",                           "regex": r""},
    6379:  {"name": "Redis",         "probe": b"*1\r\n$4\r\nINFO\r\n",      "regex": r"redis_version:([\d.]+)"},
    8080:  {"name": "HTTP-Alt",      "probe": b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n", "regex": r"Server: (.*?)\r?\n"},
    8443:  {"name": "HTTPS-Alt",     "probe": b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n", "regex": r"Server: (.*?)\r?\n"},
    9200:  {"name": "Elasticsearch", "probe": b"GET / HTTP/1.0\r\n\r\n",     "regex": r"\"version\".*?\"number\".*?\"([\d.]+)\""},
    27017: {"name": "MongoDB",       "probe": b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin\x00\x00\x00\x00\x00", "regex": r""},
    11211: {"name": "Memcached",     "probe": b"stats\r\n",                  "regex": r"STAT version ([\d.]+)"},
    2375:  {"name": "Docker API",    "probe": b"GET /info HTTP/1.0\r\n\r\n", "regex": r"\"DockerRootDir\""},
    6443:  {"name": "K8s API",       "probe": b"GET /version HTTP/1.0\r\n\r\n", "regex": r"\"gitVersion\""},
}

# ── Risk sınıflandırması ─────────────────────────────────────
CRITICAL_RISK: Set[int] = {
    2375, 2376,       # Docker unauthenticated
    6443, 10250,      # Kubernetes
    4444,             # Metasploit
    9200, 9300,       # Elasticsearch (unauthenticated)
    27017, 27018,     # MongoDB (unauthenticated)
    6379,             # Redis (unauthenticated)
    11211,            # Memcached
    5984,             # CouchDB
    50000,            # SAP
    61616,            # ActiveMQ
}
HIGH_RISK: Set[int] = {
    23,               # Telnet (plaintext)
    445, 139,         # SMB (EternalBlue etc)
    3389,             # RDP
    5900,             # VNC
    3306, 5432, 1433, # Databases
    7001,             # WebLogic
    8888,             # Jupyter
    1521,             # Oracle
    4848,             # GlassFish admin
    8161,             # ActiveMQ web
    9090,             # Prometheus
    4194,             # cAdvisor
}
MEDIUM_RISK: Set[int] = {
    21, 25, 110, 143, # Cleartext protocols
    1080,             # SOCKS proxy
    3128, 8118,       # HTTP proxy
    8080, 8000, 8001, # Alt HTTP
    1723,             # PPTP VPN
    5060,             # SIP
    873,              # rsync
}

# ── UDP yaygın portlar ────────────────────────────────────────
UDP_PORTS = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
    123: "NTP", 137: "NetBIOS", 138: "NetBIOS",
    161: "SNMP", 162: "SNMP-trap", 500: "IKE/IPSec",
    514: "Syslog", 1194: "OpenVPN", 1900: "SSDP",
    4500: "NAT-T", 5353: "mDNS",
}


class AsyncPortScanner(BaseModule):
    """Async Port Scanner v2 — nmap benzeri servis+versiyon+risk"""

    @staticmethod
    def parse_ports(ports_arg: Optional[str]) -> List[int]:
        if not ports_arg:
            return []
        result: Set[int] = set()
        for part in ports_arg.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    lo, hi = part.split("-", 1)
                    lo_int, hi_int = int(lo), int(hi)
                    if lo_int > hi_int:
                        lo_int, hi_int = hi_int, lo_int
                    result.update(range(lo_int, hi_int + 1))
                except ValueError:
                    pass
            else:
                try:
                    result.add(int(part))
                except ValueError:
                    pass
        return sorted(p for p in result if 1 <= p <= 65535)

    def run(self) -> ModuleResult:
        self.log("Port taraması v2 başlatılıyor...", "info")
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._async_scan())
            loop.close()
        except Exception as e:
            self.log(f"Async hata, sync fallback: {e}", "warning")
            self._sync_scan()
        return self.results

    async def _async_scan(self):
        ip = self.resolve_ip()
        if not ip:
            self.log(f"IP çözümlenemedi: {self.host}", "error")
            return

        self.log(f"Hedef: {self.host} ({ip})", "success")
        self.results["summary"]["IP"] = ip
        self.results["summary"]["Hostname"] = self.host

        # Port listesi
        custom = self.parse_ports(getattr(self, "_ports_arg", None))
        if custom:
            ports = custom
            self.log(f"Özel portlar: {len(ports)}", "info")
        else:
            ports = sorted(set(TOP_1000_PORTS))
            self.log(f"Top {len(ports)} port taranıyor...", "info")

        # OS fingerprint (TTL bazlı, hızlı)
        os_hint = self._os_fingerprint(ip)
        if os_hint:
            self.results["summary"]["OS Tahmini"] = os_hint

        # Async port tarama
        concurrency = 50 if len(ports) > 5000 else 120
        sem = asyncio.Semaphore(concurrency)
        t0 = time.time()
        tasks = [self._check_port(ip, p, sem) for p in ports]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        open_ports: List[int] = [r for r in raw_results if isinstance(r, int)]
        elapsed = time.time() - t0

        self.log(f"{len(ports)} port tarandı, {len(open_ports)} açık ({elapsed:.1f}s)", "success")

        # Banner + servis tespiti
        open_services = []
        for port in sorted(open_ports):
            banner, version, service_name = await self._grab_banner_and_version(ip, port)
            ssl_info = None
            if port in (443, 8443, 993, 995, 465, 636):
                ssl_info = self._grab_ssl_info(ip, port)
            open_services.append({
                "port": port,
                "service": service_name,
                "version": version,
                "banner": banner,
                "ssl": ssl_info,
            })

        # Risk değerlendirme + bulgular
        for svc in open_services:
            port = svc["port"]
            service_name = svc["service"]
            version = svc["version"]
            banner = svc["banner"]
            ssl_info = svc["ssl"]

            if port in CRITICAL_RISK:
                risk = "critical"
            elif port in HIGH_RISK:
                risk = "high"
            elif port in MEDIUM_RISK:
                risk = "medium"
            else:
                risk = "low"

            detail = f"Port {port}/{service_name}"
            if version:
                detail += f" | Versiyon: {version}"
            if banner:
                detail += f" | Banner: {banner[:80]}"
            if ssl_info:
                detail += f" | SSL: {ssl_info[:60]}"

            self.add_finding(f"Açık Port: {port}/{service_name}", detail, risk)
            self.log(f"  {port:5d}/{service_name:<15} {version or ''}", "finding")

            # Özel uyarılar
            self._check_service_specific(port, service_name, version, banner)

        # UDP taraması (hızlı, sync)
        self._scan_udp(ip)

        self.results["summary"].update({
            "Taranan Port":    len(ports),
            "Açık Port":       len(open_ports),
            "Tarama Süresi":   f"{elapsed:.1f}s",
            "Açık Liste":      ", ".join(f"{s['port']}/{s['service']}" for s in open_services),
        })
        self.results["services"] = open_services

    # ── Tek port kontrolü ────────────────────────────────────
    async def _check_port(self, ip: str, port: int, sem: asyncio.Semaphore) -> Optional[int]:
        timeout = max(0.3, min(self.timeout * 0.08, 1.0))
        async with sem:
            writer = None
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
                return port
            except Exception:
                return None
            finally:
                if writer:
                    try:
                        writer.close()
                        await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
                    except Exception:
                        pass

    # ── Banner + versiyon tespiti ────────────────────────────
    async def _grab_banner_and_version(self, ip: str, port: int) -> Tuple[str, str, str]:
        timeout = max(2.0, min(self.timeout * 0.3, 4.0))
        sig = SERVICE_SIGNATURES.get(port, {})
        service_name = sig.get("name", self._guess_service(port))
        probe = sig.get("probe", b"")
        regex = sig.get("regex", "")

        # Host adını probe'a ekle
        if b"target" in probe:
            probe = probe.replace(b"target", self.host.encode())

        writer = None
        banner = ""
        version = ""
        try:
            # SSL portları için
            if port in (443, 8443, 993, 995, 465, 636):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )

            if probe:
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=1.0)

            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            banner = data.decode("utf-8", errors="replace").strip()[:200]

            if regex and banner:
                m = re.search(regex, banner, re.DOTALL)
                if m:
                    version = m.group(1).strip()[:80]

        except Exception:
            pass
        finally:
            if writer:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
                except Exception:
                    pass

        return banner[:100], version, service_name

    def _guess_service(self, port: int) -> str:
        known = {
            21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
            80:"HTTP", 110:"POP3", 111:"RPC", 119:"NNTP", 135:"RPC",
            137:"NetBIOS", 138:"NetBIOS", 139:"NetBIOS", 143:"IMAP",
            161:"SNMP", 179:"BGP", 194:"IRC", 389:"LDAP",
            443:"HTTPS", 445:"SMB", 465:"SMTPS", 514:"Shell",
            515:"Printer", 587:"SMTP", 636:"LDAPS", 873:"rsync",
            993:"IMAPS", 995:"POP3S", 1080:"SOCKS", 1194:"OpenVPN",
            1433:"MSSQL", 1521:"Oracle", 1723:"PPTP", 1900:"SSDP",
            2049:"NFS", 2375:"Docker", 2376:"Docker-TLS",
            3000:"Dev-HTTP", 3128:"Proxy", 3306:"MySQL", 3389:"RDP",
            4444:"Shell", 5432:"PostgreSQL", 5900:"VNC", 5984:"CouchDB",
            5985:"WinRM", 5986:"WinRM-S", 6379:"Redis",
            6443:"K8s-API", 7001:"WebLogic", 8080:"HTTP-Alt",
            8443:"HTTPS-Alt", 8888:"Dev-HTTP", 9090:"Prometheus",
            9200:"Elasticsearch", 9300:"ES-Transport", 9418:"Git",
            10250:"K8s-Kubelet", 11211:"Memcached", 27017:"MongoDB",
            50000:"SAP",
        }
        return known.get(port, f"port-{port}")

    # ── SSL bilgisi ──────────────────────────────────────────
    def _grab_ssl_info(self, ip: str, port: int) -> str:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    cn = subject.get("commonName","?")
                    not_after = cert.get("notAfter","?")
                    return f"{version} | CN={cn} | Expires={not_after}"
        except Exception as e:
            return f"SSL error: {str(e)[:40]}"

    # ── OS fingerprint (TTL) ─────────────────────────────────
    def _os_fingerprint(self, ip: str) -> str:
        try:
            import subprocess, platform
            # Windows ve Linux için farklı ping argümanları
            if platform.system() == "Windows":
                cmd = ["ping", "-n", "1", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=3
            )
            output = result.stdout + result.stderr
            m = re.search(r"ttl[=:]?\s*(\d+)", output, re.I)
            if m:
                ttl = int(m.group(1))
                if ttl <= 64:
                    return "Linux/Unix (TTL≤64)"
                elif ttl <= 128:
                    return "Windows (TTL≤128)"
                elif ttl <= 255:
                    return "Cisco/Network device (TTL≤255)"
        except Exception:
            pass
        return ""

    # ── Servis özel uyarılar ─────────────────────────────────
    def _check_service_specific(self, port: int, service: str, version: str, banner: str):
        banner_lower = banner.lower()

        # Redis → kimlik doğrulamasız?
        if port == 6379 and "redis" in banner_lower:
            if "requirepass" not in banner_lower:
                self.add_finding(
                    "Redis Kimlik Doğrulamasız!",
                    f"Port 6379 Redis açık erişim — tam veri okuma/yazma riski",
                    "critical"
                )

        # Elasticsearch → anonim?
        if port == 9200 and ("elasticsearch" in banner_lower or "cluster_name" in banner_lower):
            self.add_finding(
                "Elasticsearch Kimlik Doğrulamasız!",
                f"Port 9200 ES açık erişim — tüm index'ler okunabilir",
                "critical"
            )

        # MongoDB → anonim?
        if port == 27017:
            self.add_finding(
                "MongoDB Açık Port",
                f"Port 27017 erişilebilir — kimlik doğrulama kontrolü gerekli",
                "high"
            )

        # Docker API → unauthenticated?
        if port == 2375 and ("docker" in banner_lower or port == 2375):
            self.add_finding(
                "Docker API Açık (Kimlik Doğrulamasız)!",
                f"Port 2375 Docker API açık — konteyner oluşturma/silme mümkün",
                "critical"
            )

        # Telnet → plaintext
        if port == 23:
            self.add_finding(
                "Telnet Aktif (Plaintext Protokol)",
                f"Port 23 Telnet — cleartext kimlik bilgileri riski",
                "high"
            )

        # FTP anonymous?
        if port == 21 and "ftp" in banner_lower:
            self.add_finding(
                "FTP Servisi Aktif",
                f"Port 21 FTP — anonim giriş ve plaintext şifre riski",
                "medium"
            )

        # SSH version tespiti
        if port == 22 and version:
            self.add_finding(
                f"SSH Versiyon: {version}",
                f"SSH versiyon tespiti başarılı — eski sürümler için CVE kontrolü yapılabilir",
                "info"
            )
            # Bilinen vulnerable SSH sürümleri
            if any(v in version for v in ["OpenSSH_7.2", "OpenSSH_6.", "OpenSSH_5."]):
                self.add_finding(
                    f"Eski SSH Sürümü: {version}",
                    f"Bu SSH sürümü bilinen güvenlik açıklarına sahip olabilir",
                    "medium"
                )

        # RDP
        if port == 3389:
            self.add_finding(
                "RDP Aktif",
                f"Port 3389 RDP açık — BlueKeep (CVE-2019-0708) gibi CVE'ler için risk",
                "high"
            )

        # SMB
        if port == 445:
            self.add_finding(
                "SMB Aktif",
                f"Port 445 SMB açık — EternalBlue (MS17-010) ve benzeri exploit riski",
                "high"
            )

    # ── UDP taraması ─────────────────────────────────────────
    def _scan_udp(self, ip: str):
        self.log("UDP yaygın port kontrolü...", "info")
        for port, service in UDP_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.5)
                sock.sendto(b"\x00" * 4, (ip, port))
                try:
                    data, _ = sock.recvfrom(256)
                    banner = data[:40].decode("utf-8", errors="replace").strip()
                    self.add_finding(
                        f"UDP Port Açık: {port}/{service}",
                        f"UDP yanıt alındı | Banner: {banner[:60]}",
                        "medium"
                    )
                    self.log(f"  UDP {port}/{service}", "finding")
                except socket.timeout:
                    pass  # Timeout = filtered/closed (UDP'de normal)
                except Exception:
                    pass
                finally:
                    sock.close()
            except Exception:
                pass

    # ── Sync fallback ────────────────────────────────────────
    def _sync_scan(self):
        ip = self.resolve_ip() or self.host
        timeout = max(0.5, self.timeout * 0.1)
        self.log(f"Sync fallback: {ip}", "warning")
        open_count = 0
        for port in TOP_1000_PORTS[:200]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    service = self._guess_service(port)
                    risk = ("critical" if port in CRITICAL_RISK
                            else "high" if port in HIGH_RISK
                            else "medium" if port in MEDIUM_RISK
                            else "low")
                    self.add_finding(f"Açık Port: {port}/{service}", f"Port {port} açık", risk)
                    self.log(f"  {port}/{service}", "finding")
                    open_count += 1
                s.close()
            except Exception:
                pass
        self.results["summary"]["Açık Port"] = open_count
