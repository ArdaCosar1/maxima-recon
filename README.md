<p align="center">
  <img src="https://img.shields.io/badge/Modules-41-6366f1?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-SaaS-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/License-Educational-green?style=for-the-badge" />
</p>

<h1 align="center">MAXIMA RECON</h1>
<h3 align="center">Automated Security Reconnaissance Platform</h3>

<p align="center">
  <strong>41-module security scanning platform that finds vulnerabilities before attackers do.</strong><br>
  SQL Injection, XSS, SSRF, CORS, Subdomain Takeover, CVE Matching, OSINT & more — all automated.
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> &bull;
  <a href="#-saas-platform">SaaS Platform</a> &bull;
  <a href="#-modules">Modules</a> &bull;
  <a href="#-api">API</a> &bull;
  <a href="#-reports">Reports</a>
</p>

---

## What is Maxima?

Maxima is a **modular security reconnaissance framework** that combines 41 scanning modules into a single platform. Use it as a **CLI tool**, **GUI application**, or deploy it as a **full SaaS platform** with user management, subscription plans, and Stripe payments.

### Key Features

- **41 Security Modules** — SQLi, XSS, SSRF, LFI/RFI, Command Injection, CORS, JWT flaws, subdomain takeover, and more
- **6 Scan Profiles** — Web, OSINT, Vulnerability, Network, Full, Full-v2
- **Turbo Mode** — Parallel scanning in waves, 3-5x faster than sequential
- **Professional Reports** — HTML, PDF, and JSON with executive summaries and risk scores
- **SaaS Ready** — Web dashboard, REST API, JWT auth, Stripe billing, subscription plans
- **API Access** — Integrate into CI/CD pipelines with JWT or API key authentication

---

## Quick Start

### CLI Mode
```bash
# Install
pip install -r requirements.txt

# Interactive menu
python maxima.py https://target.com

# Run all 41 modules
python maxima.py https://target.com --all

# Specific scan profile
python maxima.py https://target.com --scan web
python maxima.py https://target.com --scan vuln
python maxima.py https://target.com --scan osint

# Turbo mode (3-5x faster)
python maxima.py https://target.com --all --turbo

# Single module
python maxima.py https://target.com --module 14
```

### SaaS Mode (Web Platform)
```bash
# Install SaaS dependencies
pip install -r requirements-saas.txt

# Launch
python -m saas.app

# Open browser
# Dashboard: http://localhost:8000
# API Docs:  http://localhost:8000/api/docs
```

---

## SaaS Platform

Maxima includes a **complete SaaS platform** with:

| Feature | Description |
|---------|-------------|
| **Web Dashboard** | Modern dark-theme UI — launch scans, view results, download reports |
| **User Management** | Registration, login, JWT authentication, API keys |
| **Subscription Plans** | Free / Pro / Enterprise with scan quotas and module limits |
| **Stripe Billing** | Integrated checkout, recurring payments, customer portal |
| **REST API** | Full API with Swagger documentation |
| **Background Scanning** | Scans run in background threads, results stored in DB |
| **Admin Panel** | User management, platform statistics |

### Subscription Plans

| Plan | Price | Scans/Month | Modules | Turbo | API | Reports |
|------|-------|-------------|---------|-------|-----|---------|
| **Free** | $0 | 5 | 20 | - | - | HTML |
| **Pro** | $49/mo | 100 | All 41 | Yes | Yes | HTML + PDF + JSON |
| **Enterprise** | $199/mo | Unlimited | All 41 | Yes | Yes | HTML + PDF + JSON |

### API Usage
```bash
# Register
curl -X POST https://yourdomain.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@mail.com","username":"john","password":"pass123"}'

# Start a scan
curl -X POST https://yourdomain.com/api/scans \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","scan_type":"profile","profile":"web"}'

# Get results
curl https://yourdomain.com/api/scans/SCAN_ID \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Modules

### Web Scanners (1-20)
| # | Module | Description |
|---|--------|-------------|
| 1 | Full Recon Scan | Comprehensive reconnaissance |
| 2 | Port Scanner | Top-100 TCP port scan with banner grabbing |
| 3 | Vulnerability Scanner | General vulnerability detection |
| 4 | SQL Injection | 150+ payloads, blind/time-based SQLi |
| 5 | XSS Scanner | Reflected & stored XSS detection |
| 6 | LFI/RFI Scanner | Local/Remote File Inclusion |
| 7 | Command Injection | OS command injection testing |
| 8 | SSRF Scanner | Server-Side Request Forgery |
| 9 | Subdomain Enumeration | Subdomain discovery via multiple sources |
| 10 | Directory Enumeration | Directory & file brute-forcing |
| 11 | API Fuzzer | REST API endpoint fuzzing |
| 12 | CORS Scanner | Cross-Origin misconfiguration detection |
| 13 | SSL/TLS Analyzer | Certificate & protocol analysis |
| 14 | HTTP Header Analyzer | Security headers audit |
| 15 | Technology Detector | Tech stack fingerprinting |
| 16 | JWT Analyzer | JWT token security analysis |
| 17 | Clickjacking Tester | Frame injection testing |
| 18 | Open Redirect Scanner | Unvalidated redirect detection |
| 19 | Subdomain Takeover | Dangling CNAME / takeover detection |
| 20 | Rate Limit Tester | Rate limiting policy testing |

### OSINT & Info (21-25)
| # | Module | Description |
|---|--------|-------------|
| 21 | WHOIS Lookup | Domain registration info |
| 22 | IP Geolocation | IP address location data |
| 23 | DNS Record Analysis | Full DNS record enumeration |
| 24 | Password Strength Checker | Password policy analysis |
| 25 | Hash Identifier | Hash type detection |

### Advanced (26-41)
| # | Module | Description |
|---|--------|-------------|
| 26 | WAF Detector | Web Application Firewall detection |
| 27 | TLS Version Prober | TLS version & cipher analysis |
| 28 | Redirect Chain Analyzer | Full redirect chain mapping |
| 29 | JS Crawler & Secret Scanner | JavaScript secret extraction |
| 30 | HTTP/2 Probe | HTTP/2 support analysis |
| 31 | Payload Fuzzing Engine | Generic payload fuzzing |
| 32 | Screenshot Capture | Page metadata & screenshot |
| 33 | CVE Template Engine | CVE-based template scanning |
| 34 | Redirect-Aware Header Analysis | Header analysis through redirects |
| 35 | **Async Port Scanner** | Full 65535 port scan with asyncio |
| 36 | **CVE & Exploit Matcher** | Banner-to-CVE matching via NVD |
| 37 | **Auth & Credential Tester** | Authentication testing (requires consent) |
| 38 | **OSINT Engine** | Multi-source intelligence gathering |
| 39 | **Deep SQLi Scanner** | Advanced SQL injection with WAF bypass |
| 40 | **SSTI+XXE+IDOR+GraphQL** | Modern attack vector detection |
| 41 | **Advanced Reporter** | Risk analysis & report generation |

---

## Reports

Maxima generates professional security assessment reports:

- **HTML Report** — Interactive web report with severity charts, executive summary, remediation priorities
- **PDF Report** — Print-ready document with cover page, findings table, evidence
- **JSON Report** — Machine-readable structured data for automation

Reports include:
- 0-10 Risk Score
- Severity breakdown (Critical / High / Medium / Low / Info)
- Confidence levels (Confirmed / Firm / Tentative)
- Remediation recommendations
- Evidence display

---

## Deployment

### Docker
```bash
docker compose up -d
```

### VPS (Ubuntu)
```bash
sudo ./deploy/setup-server.sh yourdomain.com admin@yourdomain.com
```

The setup script automatically installs Python, Nginx, SSL (Let's Encrypt), and configures systemd service.

### Environment Variables
```env
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///maxima_saas.db
SITE_URL=https://yourdomain.com
STRIPE_SECRET_KEY=sk_...
STRIPE_PUBLISHABLE_KEY=pk_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_PRO=price_...
STRIPE_PRICE_ENTERPRISE=price_...
```

---

## Project Structure

```
maxima_v11_final/
├── maxima.py                 # CLI application
├── maxima_gui.py             # GUI application (tkinter)
├── cogs/                     # 41 scanning modules
├── utils/
│   ├── base_module.py        # Base class for all modules
│   ├── report_generator.py   # HTML/PDF/JSON report engine
│   └── compat.py             # Colorama compatibility shim
├── plugins/                  # User-defined plugin modules
├── saas/                     # SaaS platform
│   ├── app.py                # FastAPI application
│   ├── auth.py               # JWT & API key authentication
│   ├── billing.py            # Stripe payment integration
│   ├── config.py             # Plans, limits, configuration
│   ├── models.py             # Database models (User, Scan, Payment)
│   ├── scan_engine.py        # Scan execution engine
│   ├── schemas.py            # API request/response schemas
│   └── templates/
│       ├── landing.html      # Marketing landing page
│       └── dashboard.html    # SPA web dashboard
├── deploy/
│   ├── setup-server.sh       # One-click server setup
│   ├── update.sh             # Update script
│   └── nginx.conf            # Nginx configuration
├── tests/                    # Unit & integration tests
├── Dockerfile
├── docker-compose.yml
├── requirements.txt          # CLI dependencies
└── requirements-saas.txt     # SaaS dependencies
```

---

## Legal Disclaimer

This tool is designed **exclusively for authorized security testing**. Unauthorized use against systems you do not own or have explicit permission to test is illegal and may result in criminal prosecution. Always obtain written authorization before conducting security assessments.

---

<p align="center">
  <strong>Built with Python & FastAPI</strong><br>
  <sub>41 modules &bull; 6 scan profiles &bull; Professional reports &bull; SaaS ready</sub>
</p>
