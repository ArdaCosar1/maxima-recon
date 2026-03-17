#!/usr/bin/env python3
"""
Maxima — Profesyonel Rapor Üreticisi v3
Executive summary, confidence scoring, evidence display, remediation grouping,
JSON export, risk score hesaplaması.
"""

import os, json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether
    )
    from reportlab.platypus.flowables import HRFlowable
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

# ── Renk paleti ───────────────────────────────────────────────
SEV_COLOR = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#16a34a",
    "info":     "#2563eb",
}
SEV_BG = {
    "critical": "#fff1f2",
    "high":     "#fff7ed",
    "medium":   "#fffbeb",
    "low":      "#f0fdf4",
    "info":     "#eff6ff",
}
SEV_TR = {
    "critical": "KRİTİK",
    "high":     "YÜKSEK",
    "medium":   "ORTA",
    "low":      "DÜŞÜK",
    "info":     "BİLGİ",
}
CONF_COLOR = {
    "confirmed": "#059669",
    "firm":      "#2563eb",
    "tentative": "#d97706",
}
CONF_BG = {
    "confirmed": "#ecfdf5",
    "firm":      "#eff6ff",
    "tentative": "#fffbeb",
}
CONF_TR = {
    "confirmed": "Doğrulanmış",
    "firm":      "Güçlü",
    "tentative": "Olası",
}

BRAND_PRIMARY   = "#1e293b"   # koyu lacivert
BRAND_ACCENT    = "#6366f1"   # indigo
BRAND_SURFACE   = "#f8fafc"
BRAND_BORDER    = "#e2e8f0"
BRAND_TEXT      = "#0f172a"
BRAND_MUTED     = "#64748b"


def _esc(text: str) -> str:
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


# ─────────────────────────────────────────────────────────────
class ReportGenerator:

    def __init__(self, target: str, results_store: Dict[str, Any], output_dir: str):
        self.target     = target
        self.results    = results_store
        self.output_dir = output_dir
        self.ts_full    = datetime.now().strftime("%d %B %Y, %H:%M")
        self.ts_id      = datetime.now().strftime("%Y%m%d-%H%M%S")
        os.makedirs(output_dir, exist_ok=True)

    # ── HTML escape (statik — modül-level _esc ile aynı) ─────
    @staticmethod
    def _esc(text: str) -> str:
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

    # ── Ortak yardımcılar ────────────────────────────────────
    def _collect_findings(self) -> List[Dict[str, Any]]:
        all_f: List[Dict[str, Any]] = []
        for mod_name, result in self.results.items():
            if not isinstance(result, dict):
                continue
            for f in result.get("findings", []):
                all_f.append({**f, "_module": mod_name})
        sev_order = ["critical","high","medium","low","info"]
        all_f.sort(key=lambda x: sev_order.index(x.get("severity","info")))
        return all_f

    def _severity_counts(self, findings: List[Dict]) -> Dict[str, int]:
        counts = {s: 0 for s in ["critical","high","medium","low","info"]}
        for f in findings:
            s = f.get("severity","info")
            if s in counts:
                counts[s] += 1
        return counts

    def _confidence_counts(self, findings: List[Dict]) -> Dict[str, int]:
        counts = {c: 0 for c in ["confirmed","firm","tentative"]}
        for f in findings:
            c = f.get("confidence","firm")
            if c in counts:
                counts[c] += 1
        return counts

    def _risk_level(self, counts: Dict[str, int]) -> Tuple[str, str]:
        if counts["critical"]: return "KRİTİK",   "#dc2626"
        if counts["high"]:     return "YÜKSEK",   "#ea580c"
        if counts["medium"]:   return "ORTA",     "#d97706"
        return "DÜŞÜK", "#16a34a"

    def _risk_score(self, counts: Dict[str, int]) -> float:
        """0-10 arası risk skoru hesapla."""
        total = sum(counts.values())
        if total == 0:
            return 0.0
        weighted = (counts["critical"] * 10 + counts["high"] * 7
                    + counts["medium"] * 4 + counts["low"] * 1)
        # Normalize: max possible = total * 10
        return round(min(10.0, weighted / max(total, 1)), 1)

    def _executive_summary(self, findings: List[Dict], counts: Dict[str, int]) -> Dict[str, Any]:
        """Yönetici özeti verisi üret."""
        risk = self._risk_score(counts)
        # En kritik 3 bulgu
        top3 = findings[:3]
        # Remediation grupları
        rem_groups: Dict[str, List[str]] = {}
        for f in findings:
            rem = f.get("remediation", "")
            if rem:
                rem_groups.setdefault(rem, []).append(f.get("title", ""))
        # En çok tekrarlanan remediation'lar
        sorted_rems = sorted(rem_groups.items(), key=lambda x: -len(x[1]))[:5]
        return {
            "risk_score": risk,
            "top_findings": top3,
            "remediation_priorities": sorted_rems,
            "total": sum(counts.values()),
            "counts": counts,
        }

    # ── JSON Export ──────────────────────────────────────────
    def generate_json(self) -> str:
        """Yapılandırılmış JSON rapor dosyası üret."""
        findings = self._collect_findings()
        counts   = self._severity_counts(findings)
        conf     = self._confidence_counts(findings)
        exec_sum = self._executive_summary(findings, counts)

        report = {
            "metadata": {
                "target":      self.target,
                "report_id":   f"MXR-{self.ts_id}",
                "timestamp":   datetime.now().isoformat(),
                "module_count": len(self.results),
                "generator":   "Maxima Recon Framework v11",
            },
            "summary": {
                "risk_score":        exec_sum["risk_score"],
                "risk_level":        self._risk_level(counts)[0],
                "total_findings":    exec_sum["total"],
                "severity_counts":   counts,
                "confidence_counts": conf,
            },
            "modules": {},
            "findings": [],
        }
        for mod_name, result in self.results.items():
            if not isinstance(result, dict):
                continue
            report["modules"][mod_name] = {
                "finding_count": len(result.get("findings", [])),
                "summary":       result.get("summary", {}),
            }
        for f in findings:
            entry = {
                "title":      f.get("title", ""),
                "detail":     f.get("detail", ""),
                "severity":   f.get("severity", "info"),
                "confidence": f.get("confidence", "firm"),
                "module":     f.get("_module", ""),
                "time":       f.get("time", ""),
            }
            if f.get("remediation"):
                entry["remediation"] = f["remediation"]
            if f.get("evidence"):
                entry["evidence"] = f["evidence"]
            report["findings"].append(entry)

        json_path = os.path.join(self.output_dir, "maxima_report.json")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        return json_path

    # ── HTML Raporu ───────────────────────────────────────────
    def generate_html(self) -> str:
        findings = self._collect_findings()
        counts   = self._severity_counts(findings)
        conf     = self._confidence_counts(findings)
        total    = sum(counts.values())
        risk_lbl, risk_col = self._risk_level(counts)
        exec_sum = self._executive_summary(findings, counts)
        html_path = os.path.join(self.output_dir, "maxima_report.html")

        # ── Modül özeti satırları ──
        mod_rows = ""
        for mod_name, result in self.results.items():
            if not isinstance(result, dict):
                continue
            n   = len(result.get("findings", []))
            err = result.get("error")
            if err:
                status_html = f'<span class="tag tag-error">Hata</span>'
            elif n == 0:
                status_html = f'<span class="tag tag-clean">Temiz</span>'
            else:
                crit = sum(1 for f in result["findings"] if f.get("severity") == "critical")
                high = sum(1 for f in result["findings"] if f.get("severity") == "high")
                badges = ""
                if crit: badges += f'<span class="tag tag-critical">{crit} Kritik</span>'
                if high: badges += f'<span class="tag tag-high">{high} Yüksek</span>'
                badges += f'<span class="tag tag-info">{n} bulgu</span>'
                status_html = badges
            mod_rows += f"<tr><td class='mod-name'>{_esc(mod_name)}</td><td>{status_html}</td></tr>\n"

        # ── Executive summary HTML ──
        exec_html = self._build_executive_html(exec_sum, conf)

        # ── Bulgu kartları ──
        finding_cards = ""
        for i, f in enumerate(findings, 1):
            sev    = f.get("severity", "info")
            color  = SEV_COLOR.get(sev, "#64748b")
            bg     = SEV_BG.get(sev, "#f8fafc")
            label  = SEV_TR.get(sev, sev.upper())
            mod    = f.get("_module", "")
            rem    = f.get("remediation", "")
            ev     = f.get("evidence", "")
            c      = f.get("confidence", "firm")
            c_col  = CONF_COLOR.get(c, "#2563eb")
            c_bg   = CONF_BG.get(c, "#eff6ff")
            c_lbl  = CONF_TR.get(c, c)

            evidence_html = ""
            if ev:
                evidence_html = (
                    f"<details class='evidence-block'>"
                    f"<summary>Kanit Goster</summary>"
                    f"<pre class='evidence-pre'>{_esc(ev[:1024])}</pre>"
                    f"</details>"
                )

            finding_cards += f"""
            <div class="finding-card" style="border-left:4px solid {color};background:{bg}">
              <div class="finding-header">
                <span class="sev-badge" style="background:{color}">{label}</span>
                <span class="conf-badge" style="color:{c_col};background:{c_bg};border:1px solid {c_col}">{c_lbl}</span>
                <span class="finding-num">#{i:03d}</span>
                <strong class="finding-title">{_esc(f.get('title',''))}</strong>
                <span class="finding-module">{_esc(mod)}</span>
              </div>
              <p class="finding-detail">{_esc(f.get('detail',''))}</p>
              {"<div class='finding-rem'><span class='rem-icon'>&#128295;</span><strong>Oneri: </strong>" + _esc(rem) + "</div>" if rem else ""}
              {evidence_html}
            </div>"""

        # ── Remediation grouping ──
        rem_section = self._build_remediation_grouping(findings)

        # ── Özet pasta grafiği (SVG, saf JS yok) ──
        pie_segments = self._svg_donut(counts, total)

        html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guvenlik Degerlendirme Raporu — {_esc(self.target)}</title>
<style>
:root {{
  --primary: {BRAND_PRIMARY};
  --accent:  {BRAND_ACCENT};
  --surface: {BRAND_SURFACE};
  --border:  {BRAND_BORDER};
  --text:    {BRAND_TEXT};
  --muted:   {BRAND_MUTED};
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,Arial,sans-serif;background:#f1f5f9;
      color:var(--text);line-height:1.65;font-size:14px}}
a{{color:var(--accent);text-decoration:none}}

/* ── Layout ── */
.page{{max-width:1080px;margin:0 auto;padding:40px 24px 80px}}

/* ── Cover bar ── */
.cover{{background:var(--primary);border-radius:14px;
        padding:44px 48px;margin-bottom:32px;position:relative;overflow:hidden}}
.cover::before{{content:'';position:absolute;top:-60px;right:-60px;
                width:280px;height:280px;border-radius:50%;
                background:rgba(99,102,241,.15)}}
.cover-label{{color:#94a3b8;font-size:.78rem;text-transform:uppercase;
              letter-spacing:1.5px;margin-bottom:8px}}
.cover-title{{color:#f1f5f9;font-size:1.95rem;font-weight:700;margin-bottom:6px}}
.cover-sub{{color:#94a3b8;font-size:.95rem}}
.cover-meta{{margin-top:28px;display:flex;gap:32px;flex-wrap:wrap}}
.cover-meta-item{{display:flex;flex-direction:column;gap:3px}}
.cover-meta-item .meta-label{{color:#64748b;font-size:.75rem;
                              text-transform:uppercase;letter-spacing:1px}}
.cover-meta-item .meta-value{{color:#e2e8f0;font-size:.95rem;font-weight:600}}
.risk-pill{{display:inline-block;padding:5px 20px;border-radius:20px;
            font-weight:700;font-size:.88rem;color:#fff;
            background:{risk_col};margin-top:20px}}

/* ── Cards ── */
.card{{background:#fff;border:1px solid var(--border);border-radius:12px;
       padding:28px 30px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.card-title{{color:var(--primary);font-size:1.05rem;font-weight:700;
             margin-bottom:18px;padding-bottom:12px;
             border-bottom:2px solid #e2e8f0;display:flex;
             align-items:center;gap:8px}}

/* ── Stats grid ── */
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));
             gap:14px;margin-bottom:28px}}
.stat{{background:#fff;border:1px solid var(--border);border-radius:10px;
       padding:20px 16px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.05)}}
.stat .num{{font-size:2.4rem;font-weight:800;line-height:1}}
.stat .lbl{{color:var(--muted);font-size:.72rem;text-transform:uppercase;
            letter-spacing:.8px;margin-top:4px}}

/* ── Donut chart ── */
.chart-wrap{{display:flex;align-items:center;gap:40px;flex-wrap:wrap}}
.chart-legend{{display:flex;flex-direction:column;gap:10px}}
.legend-item{{display:flex;align-items:center;gap:10px;font-size:.88rem}}
.legend-dot{{width:12px;height:12px;border-radius:50%;flex-shrink:0}}

/* ── Module table ── */
table{{width:100%;border-collapse:collapse}}
th{{background:var(--primary);color:#e2e8f0;padding:10px 14px;
    text-align:left;font-size:.78rem;text-transform:uppercase;
    letter-spacing:.6px;font-weight:600}}
tr:nth-child(even) td{{background:#f8fafc}}
td{{padding:10px 14px;border-top:1px solid var(--border);
    font-size:.88rem;color:var(--text);vertical-align:middle}}
.mod-name{{font-weight:500;color:var(--primary)}}

/* ── Tags ── */
.tag{{display:inline-block;padding:2px 9px;border-radius:10px;
      font-size:.72rem;font-weight:700;margin-right:4px}}
.tag-critical{{background:#fee2e2;color:#b91c1c}}
.tag-high{{background:#ffedd5;color:#c2410c}}
.tag-clean{{background:#dcfce7;color:#166534}}
.tag-error{{background:#fee2e2;color:#991b1b}}
.tag-info{{background:#dbeafe;color:#1d4ed8}}

/* ── Finding cards ── */
.finding-card{{border-radius:9px;padding:18px 20px;margin-bottom:14px}}
.finding-header{{display:flex;align-items:center;gap:10px;
                 margin-bottom:8px;flex-wrap:wrap}}
.sev-badge{{padding:3px 11px;border-radius:12px;font-size:.72rem;
            font-weight:800;color:#fff;letter-spacing:.4px}}
.conf-badge{{padding:2px 9px;border-radius:10px;font-size:.68rem;
             font-weight:700;letter-spacing:.3px}}
.finding-num{{color:var(--muted);font-size:.78rem;font-weight:600}}
.finding-title{{font-size:.95rem;font-weight:700;color:var(--text);flex:1}}
.finding-module{{font-size:.75rem;color:var(--muted);
                 background:#f1f5f9;padding:2px 8px;border-radius:8px}}
.finding-detail{{color:#475569;font-size:.86rem;word-break:break-word;
                 padding-left:2px;margin-top:4px}}
.finding-rem{{margin-top:10px;font-size:.84rem;color:#0f766e;
              background:#f0fdfa;border:1px solid #99f6e4;
              border-radius:7px;padding:8px 12px;display:flex;gap:8px;
              align-items:flex-start}}
.rem-icon{{font-size:.9rem;margin-top:1px;flex-shrink:0}}

/* ── Evidence ── */
.evidence-block{{margin-top:8px}}
.evidence-block summary{{cursor:pointer;font-size:.82rem;color:var(--accent);font-weight:600}}
.evidence-pre{{background:#1e293b;color:#e2e8f0;padding:12px 16px;border-radius:8px;
               font-size:.78rem;line-height:1.5;overflow-x:auto;margin-top:6px;
               white-space:pre-wrap;word-break:break-all}}

/* ── Executive summary ── */
.exec-grid{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:14px}}
.exec-score{{font-size:3rem;font-weight:900;text-align:center;padding:16px}}
.exec-score-label{{font-size:.78rem;color:var(--muted);text-align:center;margin-top:4px}}
.priority-list{{list-style:none;padding:0}}
.priority-list li{{padding:8px 12px;border-radius:8px;margin-bottom:6px;
                   font-size:.86rem;background:#f8fafc;border-left:3px solid var(--accent)}}
.priority-list .count{{color:var(--accent);font-weight:700;margin-right:6px}}

/* ── Remediation grouping ── */
.rem-group{{background:#f0fdfa;border:1px solid #99f6e4;border-radius:10px;
            padding:16px 20px;margin-bottom:12px}}
.rem-group-title{{font-weight:700;color:#0f766e;font-size:.92rem;margin-bottom:8px}}
.rem-group-items{{font-size:.84rem;color:#475569;padding-left:16px}}
.rem-group-items li{{margin-bottom:3px}}

/* ── Footer ── */
.footer{{text-align:center;color:var(--muted);font-size:.78rem;
         margin-top:56px;padding-top:24px;border-top:1px solid var(--border)}}
.footer strong{{color:var(--primary)}}

/* ── Print ── */
@media print{{
  body{{background:#fff}}
  .page{{padding:20px}}
  .cover{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  details{{display:block}}
  details>summary{{display:none}}
  details>pre{{display:block}}
}}
</style>
</head>
<body>
<div class="page">

  <!-- ── Cover ── -->
  <div class="cover">
    <div class="cover-label">Guvenlik Degerlendirme Raporu</div>
    <div class="cover-title">Maxima Penetrasyon Test Raporu</div>
    <div class="cover-sub">{_esc(self.target)}</div>
    <div class="cover-meta">
      <div class="cover-meta-item">
        <span class="meta-label">Test Tarihi</span>
        <span class="meta-value">{self.ts_full}</span>
      </div>
      <div class="cover-meta-item">
        <span class="meta-label">Rapor No</span>
        <span class="meta-value">MXR-{self.ts_id}</span>
      </div>
      <div class="cover-meta-item">
        <span class="meta-label">Calistirilan Modul</span>
        <span class="meta-value">{len(self.results)}</span>
      </div>
      <div class="cover-meta-item">
        <span class="meta-label">Toplam Bulgu</span>
        <span class="meta-value">{total}</span>
      </div>
      <div class="cover-meta-item">
        <span class="meta-label">Risk Skoru</span>
        <span class="meta-value">{exec_sum['risk_score']}/10</span>
      </div>
    </div>
    <div class="risk-pill">Genel Risk Seviyesi: {risk_lbl}</div>
  </div>

  <!-- ── Ozet istatistikler ── -->
  <div class="stats-grid">
    <div class="stat"><div class="num" style="color:#dc2626">{counts['critical']}</div><div class="lbl">Kritik</div></div>
    <div class="stat"><div class="num" style="color:#ea580c">{counts['high']}</div><div class="lbl">Yuksek</div></div>
    <div class="stat"><div class="num" style="color:#d97706">{counts['medium']}</div><div class="lbl">Orta</div></div>
    <div class="stat"><div class="num" style="color:#16a34a">{counts['low']}</div><div class="lbl">Dusuk</div></div>
    <div class="stat"><div class="num" style="color:#2563eb">{counts['info']}</div><div class="lbl">Bilgi</div></div>
    <div class="stat"><div class="num" style="color:{BRAND_ACCENT}">{total}</div><div class="lbl">Toplam</div></div>
  </div>

  <!-- ── Executive Summary ── -->
  {exec_html}

  <!-- ── Dagilim grafigi ── -->
  <div class="card">
    <div class="card-title">Bulgu Dagilimi</div>
    <div class="chart-wrap">
      {pie_segments}
      <div class="chart-legend">
        {"".join(
          f'<div class="legend-item"><span class="legend-dot" style="background:{SEV_COLOR[s]}"></span>'
          f'<span>{SEV_TR[s]}: <strong>{counts[s]}</strong></span></div>'
          for s in ["critical","high","medium","low","info"] if counts[s] > 0
        )}
        <div style="margin-top:12px;font-size:.82rem;color:var(--muted);font-weight:600">Guven Dagilimi</div>
        {"".join(
          f'<div class="legend-item"><span class="legend-dot" style="background:{CONF_COLOR[c]}"></span>'
          f'<span>{CONF_TR[c]}: <strong>{conf[c]}</strong></span></div>'
          for c in ["confirmed","firm","tentative"] if conf[c] > 0
        )}
      </div>
    </div>
  </div>

  <!-- ── Modul ozeti ── -->
  <div class="card">
    <div class="card-title">Modul Sonuclari</div>
    <table>
      <thead><tr><th>Modul</th><th>Sonuc</th></tr></thead>
      <tbody>{mod_rows}</tbody>
    </table>
  </div>

  <!-- ── Remediation Gruplama ── -->
  {rem_section}

  <!-- ── Bulgular ── -->
  <div class="card">
    <div class="card-title">Bulgular <span style="font-weight:400;color:var(--muted);font-size:.88rem">({total} adet — kritikten dusuge)</span></div>
    {"<p style='color:var(--muted);padding:12px 0'>Tarama sonucunda guvenlik acigi tespit edilmedi.</p>" if not findings else finding_cards}
  </div>

  <!-- ── Footer ── -->
  <div class="footer">
    <strong>Maxima Modular Reconnaissance Framework v11</strong> &nbsp;·&nbsp;
    Rapor No: MXR-{self.ts_id} &nbsp;·&nbsp; {self.ts_full}<br>
    <span style="margin-top:6px;display:inline-block">
      Bu rapor yalnizca yetkili guvenlik testleri kapsaminda uretilmistir.
      Gizlilik derecesi: <strong>GIZLI</strong>
    </span>
  </div>

</div><!-- .page -->
</body>
</html>"""

        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return html_path

    # ── Executive Summary HTML builder ─────────────────────────
    def _build_executive_html(self, exec_sum: Dict, conf: Dict[str, int]) -> str:
        risk = exec_sum["risk_score"]
        # Score color
        if risk >= 8:
            score_col = "#dc2626"
        elif risk >= 5:
            score_col = "#d97706"
        elif risk >= 3:
            score_col = "#ea580c"
        else:
            score_col = "#16a34a"

        # Top findings
        top_html = ""
        for f in exec_sum["top_findings"]:
            sev = f.get("severity", "info")
            col = SEV_COLOR.get(sev, "#64748b")
            lbl = SEV_TR.get(sev, sev.upper())
            top_html += (
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'
                f'<span class="sev-badge" style="background:{col};font-size:.68rem">{lbl}</span>'
                f'<span style="font-size:.88rem;font-weight:600">{_esc(f.get("title",""))}</span>'
                f'</div>'
            )

        # Priorities
        prio_html = ""
        for rem, titles in exec_sum["remediation_priorities"]:
            prio_html += (
                f'<li><span class="count">[{len(titles)}]</span>'
                f'{_esc(rem[:120])}</li>'
            )

        return f"""
  <div class="card">
    <div class="card-title">Yonetici Ozeti</div>
    <div class="exec-grid">
      <div>
        <div class="exec-score" style="color:{score_col}">{risk}</div>
        <div class="exec-score-label">Risk Skoru (0-10)</div>
        <div style="margin-top:16px">
          <div style="font-size:.82rem;font-weight:700;color:var(--primary);margin-bottom:8px">
            En Kritik Bulgular
          </div>
          {top_html if top_html else '<span style="color:var(--muted);font-size:.86rem">Bulgu yok</span>'}
        </div>
      </div>
      <div>
        <div style="font-size:.82rem;font-weight:700;color:var(--primary);margin-bottom:8px">
          Oncelikli Aksiyonlar
        </div>
        <ul class="priority-list">
          {prio_html if prio_html else '<li style="color:var(--muted)">Remediation onerisi yok</li>'}
        </ul>
        <div style="margin-top:16px">
          <div style="font-size:.82rem;font-weight:700;color:var(--primary);margin-bottom:8px">
            Guven Dagilimi
          </div>
          <div style="display:flex;gap:12px;flex-wrap:wrap">
            {"".join(
              f'<span class="conf-badge" style="color:{CONF_COLOR[c]};background:{CONF_BG[c]};border:1px solid {CONF_COLOR[c]};padding:4px 12px">'
              f'{CONF_TR[c]}: {conf[c]}</span>'
              for c in ["confirmed","firm","tentative"] if conf[c] > 0
            )}
          </div>
        </div>
      </div>
    </div>
  </div>"""

    # ── Remediation Grouping HTML ──────────────────────────────
    def _build_remediation_grouping(self, findings: List[Dict]) -> str:
        groups: Dict[str, List[str]] = {}
        for f in findings:
            rem = f.get("remediation", "")
            if rem:
                groups.setdefault(rem, []).append(f.get("title", ""))
        if not groups:
            return ""
        sorted_groups = sorted(groups.items(), key=lambda x: -len(x[1]))
        items_html = ""
        for rem, titles in sorted_groups[:10]:
            titles_li = "".join(f"<li>{_esc(t)}</li>" for t in titles[:5])
            more = f"<li>... ve {len(titles)-5} daha</li>" if len(titles) > 5 else ""
            items_html += f"""
            <div class="rem-group">
              <div class="rem-group-title">&#128295; {_esc(rem[:200])}</div>
              <div style="font-size:.78rem;color:var(--muted);margin-bottom:4px">{len(titles)} bulguyu etkiler</div>
              <ul class="rem-group-items">{titles_li}{more}</ul>
            </div>"""
        return f"""
  <div class="card">
    <div class="card-title">Iyilestirme Oncelikleri</div>
    {items_html}
  </div>"""

    # ── SVG donut chart (harici JS gerektirmez) ───────────────
    def _svg_donut(self, counts, total):
        if total == 0:
            return '<svg width="160" height="160" viewBox="0 0 160 160"><circle cx="80" cy="80" r="60" fill="none" stroke="#e2e8f0" stroke-width="22"/></svg>'

        SEV_COLORS = [SEV_COLOR[s] for s in ["critical","high","medium","low","info"]]
        values     = [counts[s] for s in ["critical","high","medium","low","info"]]
        R = 60; CX = 80; CY = 80; SW = 22
        import math

        def arc(start_angle, end_angle, r, cx, cy):
            start = math.radians(start_angle - 90)
            end   = math.radians(end_angle - 90)
            x1 = cx + r * math.cos(start)
            y1 = cy + r * math.sin(start)
            x2 = cx + r * math.cos(end)
            y2 = cy + r * math.sin(end)
            large = 1 if (end_angle - start_angle) > 180 else 0
            return f"M {x1:.2f} {y1:.2f} A {r} {r} 0 {large} 1 {x2:.2f} {y2:.2f}"

        segments = ""
        angle = 0
        for val, color in zip(values, SEV_COLORS):
            if val == 0:
                continue
            sweep = val / total * 360
            if sweep >= 360:
                sweep = 359.9
            path = arc(angle, angle + sweep, R, CX, CY)
            segments += f'<path d="{path}" fill="none" stroke="{color}" stroke-width="{SW}" stroke-linecap="butt"/>\n'
            angle += sweep

        return f'''<svg width="160" height="160" viewBox="0 0 160 160" xmlns="http://www.w3.org/2000/svg">
  <circle cx="{CX}" cy="{CY}" r="{R}" fill="none" stroke="#f1f5f9" stroke-width="{SW}"/>
  {segments}
  <text x="{CX}" y="{CY}" text-anchor="middle" dominant-baseline="middle"
        font-size="22" font-weight="bold" fill="{BRAND_TEXT}">{total}</text>
  <text x="{CX}" y="{CY+20}" text-anchor="middle" font-size="10"
        fill="{BRAND_MUTED}">bulgu</text>
</svg>'''

    # ── PDF Raporu ────────────────────────────────────────────
    def generate_pdf(self) -> Optional[str]:
        if not HAS_REPORTLAB:
            return None

        findings = self._collect_findings()
        counts   = self._severity_counts(findings)
        risk_lbl, risk_col = self._risk_level(counts)
        exec_sum = self._executive_summary(findings, counts)
        pdf_path = os.path.join(self.output_dir, "maxima_report.pdf")
        total    = sum(counts.values())

        doc = SimpleDocTemplate(
            pdf_path, pagesize=A4,
            leftMargin=2.2*cm, rightMargin=2.2*cm,
            topMargin=2*cm, bottomMargin=2.5*cm,
            title=f"Maxima Guvenlik Raporu — {self.target}",
            author="Maxima Recon Framework",
        )

        # ── Stiller ──
        COL_PRIMARY  = colors.HexColor(BRAND_PRIMARY)
        COL_ACCENT   = colors.HexColor(BRAND_ACCENT)
        COL_MUTED    = colors.HexColor(BRAND_MUTED)
        COL_BG       = colors.HexColor("#f8fafc")

        styles = getSampleStyleSheet()
        S = lambda name, **kw: ParagraphStyle(name, **kw)

        cover_label = S("cover_label", fontSize=8, textColor=COL_MUTED,
                        spaceAfter=4, fontName="Helvetica",
                        textTransform="uppercase", letterSpacing=1.2)
        cover_title = S("cover_title", fontSize=22, textColor=COL_PRIMARY,
                        spaceAfter=6, fontName="Helvetica-Bold")
        cover_sub   = S("cover_sub",   fontSize=11, textColor=COL_ACCENT,
                        spaceAfter=16, fontName="Helvetica")
        h1          = S("h1", fontSize=14, textColor=COL_PRIMARY,
                        spaceBefore=18, spaceAfter=10, fontName="Helvetica-Bold")
        h2          = S("h2", fontSize=11, textColor=COL_PRIMARY,
                        spaceBefore=10, spaceAfter=6, fontName="Helvetica-Bold")
        body        = S("body_", fontSize=9, textColor=colors.HexColor(BRAND_TEXT),
                        spaceAfter=5, leading=14, fontName="Helvetica")
        small       = S("small", fontSize=8, textColor=COL_MUTED,
                        spaceAfter=3, leading=12, fontName="Helvetica")
        rem_style   = S("rem", fontSize=8, textColor=colors.HexColor("#0f766e"),
                        spaceAfter=4, leading=12, fontName="Helvetica-Oblique")
        ev_style    = S("ev", fontSize=7.5, textColor=colors.HexColor("#475569"),
                        spaceAfter=4, leading=11, fontName="Courier")

        def HR():
            return HRFlowable(width="100%", thickness=0.8,
                               color=colors.HexColor(BRAND_BORDER), spaceAfter=10)

        story = []

        # ── Kapak ──
        story.append(Paragraph("GUVENLIK DEGERLENDIRME RAPORU", cover_label))
        story.append(Paragraph("Maxima Penetrasyon Test Raporu", cover_title))
        story.append(Paragraph(self.target, cover_sub))
        story.append(HR())

        meta_data = [
            ["Test Tarihi",    self.ts_full],
            ["Rapor No",       f"MXR-{self.ts_id}"],
            ["Hedef",          self.target],
            ["Modul Sayisi",   str(len(self.results))],
            ["Toplam Bulgu",   str(total)],
            ["Risk Skoru",     f"{exec_sum['risk_score']}/10"],
            ["Genel Risk",     risk_lbl],
        ]
        meta_table = Table(meta_data, colWidths=[5*cm, 12*cm])
        meta_table.setStyle(TableStyle([
            ("FONTNAME",  (0,0), (-1,-1), "Helvetica"),
            ("FONTNAME",  (0,0), (0,-1),  "Helvetica-Bold"),
            ("FONTSIZE",  (0,0), (-1,-1), 9),
            ("TEXTCOLOR", (0,0), (0,-1),  COL_MUTED),
            ("TEXTCOLOR", (1,0), (1,-1),  COL_PRIMARY),
            ("ROWBACKGROUNDS", (0,0), (-1,-1),
             [colors.HexColor("#f8fafc"), colors.white]),
            ("GRID",      (0,0), (-1,-1), 0.4, colors.HexColor(BRAND_BORDER)),
            ("PADDING",   (0,0), (-1,-1), 7),
            ("TEXTCOLOR", (1,6), (1,6),  colors.HexColor(risk_col)),
            ("FONTNAME",  (1,6), (1,6),  "Helvetica-Bold"),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 14))

        # ── Bulgu ozeti tablosu ──
        story.append(Paragraph("Yonetici Ozeti", h1))
        sev_data = [
            ["Seviye", "Adet", "CVSS Araligi", "Oncelik"],
            ["Kritik",  str(counts["critical"]), "9.0 - 10.0", "Acil"],
            ["Yuksek",  str(counts["high"]),     "7.0 - 8.9",  "Kisa Vadeli"],
            ["Orta",    str(counts["medium"]),   "4.0 - 6.9",  "Planli"],
            ["Dusuk",   str(counts["low"]),      "0.1 - 3.9",  "Uzun Vadeli"],
            ["Bilgi",   str(counts["info"]),     "-",          "Izleme"],
            ["TOPLAM",  str(total),              "",           ""],
        ]
        sev_colors_pdf = [
            None,
            colors.HexColor("#dc2626"),
            colors.HexColor("#ea580c"),
            colors.HexColor("#d97706"),
            colors.HexColor("#16a34a"),
            colors.HexColor("#2563eb"),
            COL_PRIMARY,
        ]
        t = Table(sev_data, colWidths=[4*cm, 2.5*cm, 4.5*cm, 4*cm])
        ts_cmds = [
            ("BACKGROUND", (0,0), (-1,0),  COL_PRIMARY),
            ("TEXTCOLOR",  (0,0), (-1,0),  colors.white),
            ("FONTNAME",   (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("GRID",       (0,0), (-1,-1), 0.4, colors.HexColor(BRAND_BORDER)),
            ("PADDING",    (0,0), (-1,-1), 7),
            ("BACKGROUND", (0,-1), (-1,-1), colors.HexColor("#f1f5f9")),
            ("FONTNAME",   (0,-1), (-1,-1), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0,1), (-1,-2),
             [colors.HexColor("#f8fafc"), colors.white]),
        ]
        for row_idx, col in enumerate(sev_colors_pdf):
            if col:
                ts_cmds.append(("TEXTCOLOR", (0, row_idx), (0, row_idx), col))
                ts_cmds.append(("FONTNAME",  (0, row_idx), (0, row_idx), "Helvetica-Bold"))
        t.setStyle(TableStyle(ts_cmds))
        story.append(t)
        story.append(Spacer(1, 14))

        # ── Modul ozeti ──
        story.append(HR())
        story.append(Paragraph("Modul Sonuclari", h1))
        mod_data = [["Modul", "Bulgu Sayisi", "Durum"]]
        for mod_name, result in self.results.items():
            if not isinstance(result, dict):
                continue
            n   = len(result.get("findings", []))
            err = result.get("error")
            status = "Hata" if err else ("Temiz" if n == 0 else f"{n} bulgu")
            mod_data.append([mod_name, str(n), status])

        mt = Table(mod_data, colWidths=[8*cm, 3*cm, 4*cm])
        mt.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0),  COL_PRIMARY),
            ("TEXTCOLOR",  (0,0), (-1,0),  colors.white),
            ("FONTNAME",   (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 8.5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1),
             [colors.HexColor("#f8fafc"), colors.white]),
            ("GRID",       (0,0), (-1,-1), 0.4, colors.HexColor(BRAND_BORDER)),
            ("PADDING",    (0,0), (-1,-1), 6),
        ]))
        story.append(mt)

        # ── Bulgular bolumu ──
        story.append(PageBreak())
        story.append(Paragraph(f"Bulgular ({total} Adet)", h1))
        story.append(HR())

        if not findings:
            story.append(Paragraph("Tarama sonucunda guvenlik acigi tespit edilmedi.", body))
        else:
            for i, f in enumerate(findings, 1):
                sev    = f.get("severity", "info")
                col    = colors.HexColor(SEV_COLOR.get(sev, "#64748b"))
                label  = SEV_TR.get(sev, sev.upper())
                c      = f.get("confidence", "firm")
                c_lbl  = CONF_TR.get(c, c)
                rem    = f.get("remediation", "")
                ev     = f.get("evidence", "")

                block = []
                block.append(Paragraph(
                    f'<font color="{SEV_COLOR.get(sev,"#64748b")}"><b>[{label}]</b></font> '
                    f'<font color="{CONF_COLOR.get(c,"#2563eb")}"><b>[{c_lbl}]</b></font>  '
                    f'<font color="{BRAND_TEXT}"><b>#{i:03d} - '
                    f'{self._esc_pdf(f.get("title",""))}</b></font>',
                    body
                ))
                block.append(Paragraph(
                    f'<font color="{BRAND_MUTED}">Modul: {self._esc_pdf(f.get("_module",""))} '
                    f'| Zaman: {f.get("time","")}</font>',
                    small
                ))
                detail = self._esc_pdf(f.get("detail",""))[:400]
                if detail:
                    block.append(Paragraph(detail, body))
                if rem:
                    block.append(Paragraph(
                        f'<i>Oneri: {self._esc_pdf(rem)}</i>',
                        rem_style
                    ))
                if ev:
                    block.append(Paragraph(
                        f'Kanit: {self._esc_pdf(ev[:300])}',
                        ev_style
                    ))
                block.append(Spacer(1, 4))

                story.append(KeepTogether(block))

        # ── Kapanis ──
        story.append(HR())
        story.append(Paragraph(
            f"Bu rapor Maxima Recon Framework tarafindan otomatik olarak uretilmistir. "
            f"Rapor No: MXR-{self.ts_id} | {self.ts_full}",
            small
        ))

        doc.build(story)
        return pdf_path

    def generate_all(self) -> Tuple[str, Optional[str], str]:
        """HTML, PDF ve JSON rapor uret. Returns (html_path, pdf_path|None, json_path)."""
        html_path = self.generate_html()
        pdf_path  = self.generate_pdf()
        json_path = self.generate_json()
        return html_path, pdf_path, json_path

    @staticmethod
    def _esc_pdf(text: str) -> str:
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))
