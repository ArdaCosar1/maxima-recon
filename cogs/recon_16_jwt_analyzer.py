#!/usr/bin/env python3
"""
Maxima Cog: JWT Analyzer
Module: JWTAnalyzer
"""
import sys
import os
import re
import base64   # BUG FIX: class body'den modül seviyesine taşındı
import json as _json  # BUG FIX: class body'den modül seviyesine taşındı
from utils.base_module import BaseModule, ModuleResult


class JWTAnalyzer(BaseModule):
    """JWT Analyzer"""

    def _decode_part(self, part):
        try:
            pad = 4 - len(part) % 4
            return _json.loads(base64.urlsafe_b64decode(part + "=" * pad))
        except Exception:
            return {}
    def run(self) -> ModuleResult:
        self.log("JWT analizi (cookie/header tarama)...")
        resp = self.http_get(self.url)
        cookies = resp.get("headers",{}).get("set-cookie","")
        tokens = re.findall(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", cookies)
        for token in tokens:
            parts = token.split(".")
            if len(parts) == 3:
                header  = self._decode_part(parts[0])
                payload = self._decode_part(parts[1])
                alg = header.get("alg","")
                if alg.lower() == "none":
                    self.add_finding("JWT None Algorithm", "JWT alg:none - imza doğrulaması yok!", "critical")
                elif alg.lower() in ["hs256","hs384","hs512"]:
                    self.add_finding("JWT Simetrik Algoritma", f"Algoritma: {alg}", "medium")
                self.results["summary"]["JWT Algoritma"] = alg
                if "exp" not in payload:
                    self.add_finding("JWT Süre Sınırı Yok", "exp claim eksik", "high")
        self.results["summary"]["Bulunan Token"] = len(tokens)
        return self.results

