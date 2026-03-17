#!/usr/bin/env python3
"""
Maxima Cog: HTTP/2 Probe & Async Port Scan
Module: HTTP2Probe
"""
import sys
import os
import socket
import ssl
import threading
from utils.base_module import BaseModule, ModuleResult


class HTTP2Probe(BaseModule):
    """HTTP/2 Probe & Async Port Scan"""

    def run(self) -> ModuleResult:
        self.log("HTTP/2 ve async port taraması...")
        # HTTP/2 check via ALPN
        http2_supported = False
        try:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["h2","http/1.1"])
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, 443), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=self.host) as ss:
                    proto = ss.selected_alpn_protocol()
                    if proto == "h2":
                        http2_supported = True
                        self.log("HTTP/2 destekleniyor", "success")
                        self.results["summary"]["HTTP/2"] = "Destekleniyor"
                    else:
                        self.results["summary"]["HTTP/2"] = f"Desteklenmiyor ({proto})"
        except Exception as e:
            self.results["summary"]["HTTP/2"] = f"Test edilemedi: {str(e)[:40]}"
        # Async port scan
        PORTS = [22,80,443,8080,8443,3000,4000,5000,8000,9000]
        open_ports = []
        lock = threading.Lock()
        def check(port):
            try:
                s = socket.socket()
                s.settimeout(max(1, self.timeout // 4))
                if s.connect_ex((self.host, port)) == 0:
                    with lock: open_ports.append(port)
                s.close()
            except (OSError, socket.error):
                pass
        threads = [threading.Thread(target=check, args=(p,), daemon=True) for p in PORTS]
        for t in threads: t.start()
        # BUG FIX: join timeout eklendi — yanıtsız hedeflerde sonsuz bekleme önlendi
        for t in threads: t.join(timeout=max(2, self.timeout // 2))
        if open_ports:
            self.results["summary"]["Açık Portlar"] = str(open_ports)
            self.add_finding("Açık Portlar", f"Portlar: {open_ports}", "info")
        return self.results

