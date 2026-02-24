# WebCure — Website Vulnerability Assessment System

> **Free, browser-based web security scanner aligned with OWASP Top 10 (2021)**  
> Scan any public website for 50+ security issues in ~20 seconds. Get plain-English results, an A–F safety grade, and a professional PDF audit report — no installation, no expertise required.

---

## 🔍 What is WebCure?

WebCure is an automated vulnerability scanner built as a Winter Pep academic project at **Lovely Professional University**. It checks publicly accessible websites for security weaknesses across all **OWASP Top 10 (2021)** categories and communicates findings in plain English — making professional-grade security accessible to developers, students, and non-technical website owners alike.

```
User enters URL → Flask validates → 11 modules scan concurrently → A–F grade + PDF report
```

---

## ✨ Features

- **50+ security checks** across all OWASP Top 10 (2021) categories
- **A–F Safety Grade** — instant, plain-English risk verdict
- **Plain-English findings** — no jargon, just "what it means" and "how to fix it"
- **Professional PDF report** — suitable for sharing with developers or IT teams
- **~20 second scan time** — powered by concurrent ThreadPoolExecutor
- **Zero installation** — runs entirely in the browser
- **SSRF protection** — blocks scans against private/internal networks
- **Completely free** — no account, no API keys, no cost

---

## 🛡️ Security Coverage

| OWASP ID | Category | What WebCure Checks |
|----------|----------|---------------------|
| A01:2021 | Broken Access Control | Sensitive paths (/.env, /.git), directory listing, HTTP methods |
| A02:2021 | Cryptographic Failures | SSL/TLS cert expiry, protocol version, cipher strength |
| A03:2021 | Injection | SQL Injection + XSS via payload testing in params & forms |
| A05:2021 | Security Misconfiguration | 8 security headers, CORS policy, open ports (9 types) |
| A06:2021 | Vulnerable Components | Server version fingerprinting, SRI missing on scripts |
| A07:2021 | Auth Failures | Cookie flags (HttpOnly, Secure, SameSite), CSRF tokens |
| A08:2021 | Integrity Failures | External scripts without Subresource Integrity |
| A09:2021 | Logging Failures | Stack traces, verbose PHP/Python/MySQL error disclosure |
| A10:2021 | SSRF / Open Redirect | Open redirect params, SSRF payload probing |
| — | DNS Security | SPF, DMARC, CAA records, DNS zone transfer |

---

## 🗂️ Project Structure

```
webcure/
│
├── backend.py          # Flask API + all 11 scan modules + PDF generator
├── frontend/
│   └── index.html      # Browser UI — plain-English results, A–F grade
├── requirements.txt    # Python dependencies
└── README.md
```

---

## ⚙️ Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Web Framework | Python Flask |
| Cross-Origin | Flask-CORS |
| HTTP Client | Requests |
| HTML Parsing | BeautifulSoup4 |
| DNS Analysis | dnspython |
| SSL Inspection | ssl + cryptography |
| Concurrency | ThreadPoolExecutor |
| PDF Generation | ReportLab |
| Standard Library | socket, ipaddress, re, urllib.parse |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/webcure.git
cd webcure

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the backend
python backend.py
```

The server starts on `http://localhost:5000`

### Usage

1. Open `frontend/index.html` in your browser  
   *(or visit `http://localhost:5000` if Flask serves static files)*
2. Enter any public website URL (e.g. `https://example.com`)
3. Click **Check Now** and wait ~20 seconds
4. Review your A–F grade and plain-English findings
5. Click **Download PDF Report** to get the full audit document

### API Endpoints

```
POST /api/scan      →  Run full OWASP scan, returns JSON results
POST /api/report    →  Generate and download PDF report
GET  /api/health    →  Health check — returns tool info
```

**Example scan request:**
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

---

## 📦 Requirements

Create a `requirements.txt` with:

```
flask
flask-cors
requests
beautifulsoup4
dnspython
cryptography
reportlab
```

Install with:
```bash
pip install -r requirements.txt
```

---

## 📄 Output — PDF Report

The generated PDF includes:

- **Cover page** with target URL, scan date, risk score, and classification
- **Executive summary** with severity breakdown table
- **Scope & Methodology** section
- **Per-finding cards** with evidence, CVSS score, and remediation
- **OWASP Top 10 reference** table
- **Legal disclaimer**

---

## ⚠️ Legal & Ethical Use

> **Only scan websites you own or have explicit written permission to test.**  
> WebCure includes SSRF protection that automatically blocks scans against private and internal IP addresses.  
> Unauthorized scanning of systems you do not own may be illegal in your jurisdiction.

This tool is built for:
- ✅ Scanning your own websites
- ✅ Academic security research
- ✅ Authorized security audits
- ❌ Scanning third-party websites without permission

---

## 🔮 Future Scope

- [ ] Scheduled weekly scans with email alerts
- [ ] Authenticated scanning (behind-login pages)
- [ ] AI-powered plain-English fix recommendations
- [ ] Browser extension for real-time site checking
- [ ] Security trend dashboard over time
- [ ] CI/CD pipeline integration

---

## 👤 Author

**Chandransh Ranjan**  
B.Tech Computer Science & Engineering  
Lovely Professional University  
Winter Pep Project 2025-26

---

## 📚 References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [ReportLab PDF Library](https://www.reportlab.com/docs/)

---

*WebCure v2.4 — For authorized security testing only*
