# 🦅 AuditHawk  
Async Recon & Quick-Audit Framework for Pentesters  

AuditHawk is a **fast, safe, and extensible reconnaissance framework** for penetration testers and bug bounty hunters.  
It performs non-destructive checks like HTTP probing, header analysis, common path discovery, and plugin-based fingerprinting — with optional screenshots and HTML reports for quick triage.  

---

## ✨ Features
- 🌐 **Subdomain discovery** (via [subfinder](https://github.com/projectdiscovery/subfinder) / [amass](https://github.com/owasp-amass/amass) if installed)  
- ⚡ **Async HTTP probing** — concurrent, efficient scanning  
- 📋 **Security header audit** — detect missing CSP, HSTS, etc.  
- 🔍 **Common file/path checks** (`/.env`, `/admin`, `/login`, etc.)  
- 🧩 **Plugin system** — extend with your own checks (`plugins/*.py`)  
- 🖼 **Screenshots** via Playwright (optional)  
- 📊 **Reports** in JSON, CSV, and HTML  

---

## 📦 Installation

Clone the repo:

git clone https://github.com/yourusername/AuditHawk.git
cd AuditHawk

Run installer:

./install.sh


With Playwright browsers (for screenshots):

./install.sh --with-playwright


Activate environment:

source .venv/bin/activate

🚀 Usage

Single target:

python3 pentool.py --target example.com --output results.json --csv summary.csv --plugins plugins


Multiple targets:

python3 pentool.py --targets examples/hosts.txt --use-subfinder --screenshot --plugins plugins --output results.json --csv summary.csv --html report.html


Help:

python3 pentool.py --help

🔌 Plugins

Three example plugins are included in plugins/
:

cms_fingerprint.py → detects WordPress/Drupal

s3_probe.py → checks for open or restricted S3 buckets

admin_probe.py → finds common admin portals

👉 Create your own plugin by adding a file to plugins/ with:

async def run(session, base, results):
    # return dict of findings

📊 Output

results.json → full structured data

summary.csv → compact summary for spreadsheets

report.html → interactive HTML report with screenshots

Example report entry:

host: example.com
status: 200
title: Example Domain
server: nginx
missing headers: content-security-policy, referrer-policy
notes: server banner: nginx | possible admin/login page: https://example.com/admin

📂 Project Structure
AuditHawk/
├── pentool.py          # main tool
├── install.sh          # installer
├── requirements.txt    # Python dependencies
├── README.md           # this file
├── .gitignore
├── plugins/
│   ├── cms_fingerprint.py
│   ├── s3_probe.py
│   ├── admin_probe.py
│   └── __init__.py
├── examples/
│   └── hosts.txt
└── screenshots/        # created automatically if --screenshot used

🛠 Roadmap

 More built-in plugins (CMS, WAF, API key exposure)

 Slack/Telegram alert integrations

 CI workflow for scheduled scans

 Optional Docker support

🤝 Contributing

Contributions are welcome!
Open an issue
 or submit a pull request with improvements.
