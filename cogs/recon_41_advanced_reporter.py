#!/usr/bin/env python3
"""
Maxima Cog: Gelişmiş Raporlama Motoru
FIX:
  - chart_path'te self.host içinde "/" veya ":" olabilir (host:port) — sanitize edildi
  - matplotlib import hatası daha sağlam yakalanıyor
"""
import os, re, json, time
from utils.base_module import BaseModule, ModuleResult
from datetime import datetime

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MPL = True
except Exception:
    HAS_MPL = False

CVSS_PRESETS = {
    "critical": {"score": 9.5, "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
    "high":     {"score": 7.5, "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"},
    "medium":   {"score": 5.0, "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"},
    "low":      {"score": 2.5, "vector": "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"},
    "info":     {"score": 0.0, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
}

REMEDIATION = {
    "SQL Injection":    "Parametreli sorgu (prepared statement) kullanın. ORM tercih edin.",
    "XSS":              "Tüm kullanıcı girdilerini encode edin. CSP başlığı ekleyin.",
    "CVE":              "Sistemi en son güvenli versiyona güncelleyin.",
    "SSTI":             "Kullanıcı girdisini template motoru değişkeni olarak kullanmayın.",
    "XXE":              "XML işleyicide external entity'yi devre dışı bırakın.",
    "IDOR":             "Her obje erişiminde oturum sahibi yetki kontrolü yapın.",
    "Path Traversal":   "Dosya yollarını whitelist ile doğrulayın, canonical path kullanın.",
    "Open Redirect":    "Yönlendirme URL'lerini whitelist ile filtreleyin.",
    "CORS":             "Origin whitelist ile CORS politikasını kısıtlayın.",
    "Açık Port":        "Gereksiz servisleri kapatın, firewall kurallarını gözden geçirin.",
    "Default":          "Varsayılan kimlik bilgilerini değiştirin.",
    "Session":          "HttpOnly, Secure, SameSite=Strict cookie flag kullanın.",
    "HSTS":             "Strict-Transport-Security başlığını ekleyin (max-age≥31536000).",
    "CSP":              "Content-Security-Policy başlığını yapılandırın.",
}


def _safe_filename(s: str) -> str:
    """Host/path string'ini dosya adı güvenli hale getir."""
    return re.sub(r'[^\w\-]', '_', s)[:40]


class AdvancedReporter(BaseModule):
    """Gelişmiş Raporlama Motoru — CVSS, grafik, executive summary"""

    def run(self) -> ModuleResult:
        self.log("Gelişmiş raporlama motoru çalışıyor...")
        all_findings = self._collect_all_findings()

        counts = self._count_by_severity(all_findings)
        risk   = self._overall_risk(counts)

        self.results["summary"]["Toplam Bulgu"]  = len(all_findings)
        self.results["summary"]["Risk Seviyesi"] = risk
        self.results["summary"]["Kritik"]        = counts.get("critical", 0)
        self.results["summary"]["Yüksek"]        = counts.get("high", 0)
        self.results["summary"]["Orta"]          = counts.get("medium", 0)
        self.results["summary"]["Düşük"]         = counts.get("low", 0)

        for f in all_findings:
            sev  = f.get("severity","info").lower()
            cvss = CVSS_PRESETS.get(sev, CVSS_PRESETS["info"])
            f["cvss_score"]  = cvss["score"]
            f["cvss_vector"] = cvss["vector"]
            rem = "Güvenlik ekibiyle değerlendirin."
            for key, val in REMEDIATION.items():
                if key.lower() in f.get("title","").lower():
                    rem = val
                    break
            f["remediation"] = rem
            self.results["findings"].append(f)

        if HAS_MPL:
            self._generate_charts(counts)
        else:
            self.log("matplotlib yok — grafik atlandı", "warning")

        return self.results

    def _collect_all_findings(self):
        """Tüm modül bulgularını topla — imported_results varsa oradan, yoksa yerel findings."""
        imported = self.results.get("imported_results", {})
        if imported:
            all_f = []
            for mod_result in imported.values():
                if isinstance(mod_result, dict):
                    all_f.extend(mod_result.get("findings", []))
            return all_f
        return self.results.get("findings", [])

    def _count_by_severity(self, findings):
        counts = {}
        for f in findings:
            s = f.get("severity","info").lower()
            counts[s] = counts.get(s, 0) + 1
        return counts

    def _overall_risk(self, counts):
        if counts.get("critical", 0) > 0:
            return "KRİTİK"
        if counts.get("high", 0) > 0:
            return "YÜKSEK"
        if counts.get("medium", 0) > 0:
            return "ORTA"
        if counts.get("low", 0) > 0:
            return "DÜŞÜK"
        return "BİLGİ"

    def _generate_charts(self, counts):
        try:
            labels = [k.upper() for k in counts.keys() if counts[k] > 0]
            values = [counts[k] for k in counts.keys() if counts[k] > 0]
            colors = {
                "CRITICAL":"#e74c3c","HIGH":"#e67e22",
                "MEDIUM":"#f1c40f","LOW":"#3498db","INFO":"#95a5a6"
            }
            bar_colors = [colors.get(l,"#bdc3c7") for l in labels]

            fig, ax = plt.subplots(figsize=(8, 4))
            ax.bar(labels, values, color=bar_colors, edgecolor="white", linewidth=1.5)
            ax.set_title("Bulgu Dağılımı", fontsize=14, fontweight="bold")
            ax.set_ylabel("Adet")
            ax.grid(axis="y", linestyle="--", alpha=0.4)

            # FIX: host'ta ":" veya "/" olabilir — sanitize et
            safe_host = _safe_filename(self.host)
            out_dir   = os.path.dirname(os.path.abspath(__file__))
            chart_path = os.path.join(out_dir, "..", f"chart_{safe_host}_{int(time.time())}.png")
            chart_path = os.path.normpath(chart_path)
            fig.savefig(chart_path, dpi=120, bbox_inches="tight")
            plt.close(fig)
            self.results["summary"]["Grafik"] = chart_path
            self.log(f"Grafik kaydedildi: {chart_path}", "success")
        except Exception as e:
            self.log(f"Grafik hatası: {e}", "warning")
