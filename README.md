<div align="center">

<img src="assets/logo.jpg" alt="SOCNeon Logo" width="120" height="120" style="border-radius:20px"/>

# 🛡️ SOCNeon

### Privacy-First SOC Log Analyzer

**Analyze security logs 100% in your browser. No uploads. No accounts. No telemetry.**

[![Live Demo](https://img.shields.io/badge/🌐%20Live%20Demo-GitHub%20Pages-00e5ff?style=for-the-badge)](https://ramaneon.github.io/socneon/)
[![Version](https://img.shields.io/badge/version-2.0.0-7b2fff?style=for-the-badge)](#)
[![License](https://img.shields.io/badge/license-MIT-00ff9d?style=for-the-badge)](LICENSE)
[![Offline](https://img.shields.io/badge/works-100%25%20offline-00ff9d?style=for-the-badge)](#)
[![No Backend](https://img.shields.io/badge/backend-none%20required-ff3860?style=for-the-badge)](#)

---

[**🚀 Open SOCNeon →**](https://ramaneon.github.io/socneon/) &nbsp;·&nbsp; [Features](#-features) &nbsp;·&nbsp; [Supported Formats](#-supported-log-formats) &nbsp;·&nbsp; [Detection Rules](#-detection-rules) &nbsp;·&nbsp; [Deploy](#-deploy-your-own)

</div>

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔒 Privacy First
Zero network requests during analysis. All parsing and detection runs entirely in JavaScript inside your browser tab. Works air-gapped. Source is fully auditable.

### ⚡ Multi-Format Parsing
Auto-detects and parses **CSV**, **JSON arrays**, **JSONL/NDJSON**, **RFC 3164 syslog**, **RFC 5424 syslog**, **Apache/Nginx Common Log Format**, and plain-text logs.

### 🎯 22 Detection Rules
Explainable rules covering Brute Force, SQL Injection, XSS, Path Traversal, Port Scans, Data Exfiltration, Lateral Movement, Malware C2, and more. Every alert shows **why** it fired.

### 🗺️ MITRE ATT&CK Mapping
Detected techniques are mapped to the ATT&CK framework across 12 tactics. Interactive clickable grid — click any fired technique to see matching alerts.

</td>
<td width="50%">

### 🔗 Correlation Engine
Events are grouped by source IP and analyzed for kill chain progression (Recon → Initial Access → Execution → Persistence → C2 → Exfiltration). Multi-stage attack chains are highlighted.

### 💉 IOC Extraction
Auto-extracts all Indicators of Compromise: IP addresses (internal vs. external), URLs, file hashes (MD5/SHA1/SHA256), usernames, hostnames, CVE IDs, and email addresses.

### ⚙️ Custom Rules Builder
Create your own detection rules with a point-and-click UI. Choose field, operator (contains/equals/regex/gt/lt), value, and severity. Rules are saved to `localStorage` and persist between sessions.

### 📄 Report Export
Generate a full security report as a printable HTML document. Also export alerts and events as CSV or JSON. Extract all IOCs as a single JSON file.

</td>
</tr>
</table>

---

## 🖥️ Screenshots

<div align="center">

| Landing Page | Alerts Dashboard |
|:---:|:---:|
| *Drop any log file — auto-detected* | *Explainable alerts with MITRE tags* |

| Timeline Charts | MITRE ATT&CK Grid |
|:---:|:---:|
| *Canvas charts: timeline, donut, heatmap, gauge* | *Interactive technique matrix* |

| Correlation Chains | Custom Rules Builder |
|:---:|:---:|
| *Kill chain visualization by source IP* | *Point-and-click rule creation* |

</div>

---

## 📂 Supported Log Formats

### CSV — Auto-detected header row
```
timestamp,src_ip,dst_ip,dst_port,action,message
2024-03-15T08:00:00Z,192.168.1.1,10.0.0.5,22,deny,Failed password for root
```
> ✅ 50+ field aliases auto-normalized (`@timestamp`, `event_time`, `remote_addr`, etc.)

### JSON Array — Flat or nested (auto-flattened)
```json
[{"@timestamp":"2024-03-15T08:00:00Z","source":{"ip":"1.2.3.4"},"message":"..."}]
```

### JSONL / NDJSON — One object per line
```
{"timestamp":"2024-03-15T08:00:00Z","src_ip":"1.2.3.4","message":"..."}
{"timestamp":"2024-03-15T08:00:01Z","src_ip":"5.6.7.8","message":"..."}
```

### Syslog — RFC 3164, RFC 5424, plain text
```
<38>Mar 15 08:00:05 auth01 sshd[1234]: Failed password for root from 1.2.3.4
```

---

## 🎯 Detection Rules

| ID | Rule | Severity | Category |
|----|------|----------|----------|
| AUTH-001 | Brute-Force Login Attempt | 🔴 High | Authentication |
| AUTH-002 | Successful Login After Multiple Failures | 🔴 High | Authentication |
| AUTH-003 | Login from Unusual Hour (00:00–05:00) | 🟡 Medium | Authentication |
| NET-001 | Port Scan Detected (≥10 ports/min) | 🔴 High | Network |
| NET-002 | Connection to Known Malicious Port | 🔴 High | Network |
| NET-003 | Large Data Exfiltration (>100 MB) | 🔴 High | Network |
| NET-004 | Internal Lateral Movement (SMB/RDP/SSH) | 🟡 Medium | Network |
| NET-005 | DNS Tunneling Indicator | 🟡 Medium | Network |
| WEB-001 | SQL Injection Attempt | ⛔ Critical | Web Attack |
| WEB-002 | Cross-Site Scripting (XSS) Attempt | 🔴 High | Web Attack |
| WEB-003 | Path Traversal Attempt | 🔴 High | Web Attack |
| WEB-004 | Security Scanner Detected (nikto, sqlmap…) | 🟡 Medium | Web Attack |
| WEB-005 | HTTP Error Storm (4xx/5xx spike) | 🟡 Medium | Web Attack |
| SYS-001 | Privileged Command Execution (mimikatz, psexec…) | 🔴 High | Endpoint |
| SYS-002 | New User Account Created | 🟡 Medium | Endpoint |
| SYS-003 | Scheduled Task / Cron Created | 🟡 Medium | Endpoint |
| SYS-004 | Known Malware File Hash | ⛔ Critical | Endpoint |
| FW-001 | Firewall Deny Traffic Spike | 🟡 Medium | Firewall |
| MAL-001 | Known C2 Domain / IP | ⛔ Critical | Malware |
| MAL-002 | Base64 Encoded Command (PowerShell -enc) | 🔴 High | Malware |
| ANOM-001 | Service Account Interactive Login | 🟡 Medium | Anomaly |
| ANOM-002 | High-Frequency Event Flooding | 🔵 Low | Anomaly |

---

## 🚀 Deploy Your Own

### Option 1 — Fork & Enable Pages (30 seconds)

1. **Fork** this repository: click `Fork` at the top right
2. Go to your fork → **Settings → Pages**
3. Source: **Deploy from a branch** → `main` → `/ (root)`
4. Click **Save**
5. Your instance will be live at `https://YOUR-USERNAME.github.io/socneon/`

### Option 2 — Clone & Push

```bash
git clone https://github.com/ramaneon/socneon.git
cd socneon
# Make changes
git add . && git commit -m "my changes"
git push
# GitHub Pages auto-deploys via the included workflow
```

### Option 3 — Run Locally (no build step)

```bash
# Python
python -m http.server 8080
# → http://localhost:8080

# Node.js
npx serve .
# → http://localhost:3000

# Or just open index.html directly in Chrome/Edge
```

---

## 🔮 Future Features (Backend Required)

These features are clearly marked in the UI as requiring a backend:

| Feature | Notes |
|---------|-------|
| 🔮 Live Threat Intel Feed | MISP, AlienVault OTX, VirusTotal API |
| 🔮 SIEM Push | Splunk, Elastic, QRadar connectors |
| 🔮 AI-Powered Enrichment | LLM-based alert summarization |
| 🔮 Multi-File Correlation | Cross-session log correlation |
| 🔮 Persistent Case Management | Analyst notes, ticket tracking |

---

## 🔐 Privacy & Security

- **Zero exfiltration** — No data is ever sent anywhere. Proven by reading the source.
- **No localStorage for log data** — Only custom rules and alert notes are persisted locally.
- **XSS-safe rendering** — All log content is HTML-entity-escaped before display. Never rendered as raw HTML.
- **No third-party analytics** — No Google Analytics, no tracking pixels, no CDN calls during analysis.
- **Fonts load once** — Google Fonts is the only external request, made on page load, not during analysis.

### Recommended CSP (for self-hosted hardening)
```
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; script-src 'self'; connect-src 'none';
```

---

## 🗂️ Project Structure

```
socneon/
├── index.html                    # Single-page app entry point
├── css/
│   └── styles.css                # Dark cyberpunk theme (1500+ lines)
├── js/
│   ├── parser.js                 # Multi-format log parser + field normalization
│   ├── rules.js                  # 22 explainable detection rules engine
│   ├── charts.js                 # Pure Canvas chart library (no dependencies)
│   ├── advanced.js               # IOC extraction, MITRE, correlation, custom rules
│   ├── demo-data.js              # Realistic synthetic log samples
│   └── app.js                    # Main UI controller (9 tabs, search, export)
├── assets/
│   └── logo.jpg                  # SOCNeon brand logo
├── .github/
│   └── workflows/
│       └── deploy.yml            # GitHub Actions auto-deploy to Pages
├── README.md
└── LICENSE
```

---

## 🛠️ Extending SOCNeon

### Add a Detection Rule

Edit [`js/rules.js`](js/rules.js) and add to the `RULES` array:

```javascript
{
  id: 'CUSTOM-001',
  title: 'My Detection Rule',
  severity: SEVERITY.HIGH,
  category: 'Custom',
  description: 'What this rule detects.',
  check(event, allEvents) {
    if (!event.message?.includes('suspicious')) return null;
    return {
      matched: true,
      confidence: 80,
      explanation: 'Found "suspicious" keyword in message field.',
      evidence: { message: event.message?.slice(0, 100) },
    };
  },
},
```

### Add Custom IOCs (Threat Intel)

In [`js/rules.js`](js/rules.js), find rule `MAL-001` and extend the indicator lists:

```javascript
const BAD_DOMAINS = ['evil.com', 'your-ioc-domain.net', ...];
const BAD_IPS     = ['1.2.3.4', 'your-c2-ip', ...];
```

### Field Normalization Aliases

Add your custom field names to the `FIELD_ALIASES` map in [`js/parser.js`](js/parser.js):

```javascript
src_ip: ['src_ip', 'source_ip', 'your_custom_field', ...],
```

---

## 🌐 Browser Support

| Browser | Version | Support |
|---------|---------|---------|
| Chrome | 90+ | ✅ Full |
| Firefox | 88+ | ✅ Full |
| Edge | 90+ | ✅ Full |
| Safari | 14+ | ✅ Full |
| Mobile Chrome | Any | ✅ Responsive |
| Mobile Safari | iOS 14+ | ✅ Responsive |

---

## 📜 License

MIT © 2024 [ramaneon](https://github.com/ramaneon)

Free for personal and commercial use. Attribution appreciated but not required.

---

<div align="center">

**SOCNeon** — *Because your logs are yours.*

Made with ⚡ by [ramaneon](https://github.com/ramaneon)

[🌐 Live Demo](https://ramaneon.github.io/socneon/) · [🐛 Issues](https://github.com/ramaneon/socneon/issues) · [⭐ Star this repo](https://github.com/ramaneon/socneon)

</div>
