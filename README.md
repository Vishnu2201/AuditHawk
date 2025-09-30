# 🦅 AuditHawk  
**Async Recon + Plugin Framework + Screenshots + Reporting**  

AuditHawk is a modern, lightweight reconnaissance and auditing tool for pentesters, bug bounty hunters, and security researchers.  
It combines fast async scanning, plugin-based extensibility, and beautiful HTML/CSV/JSON reports — all in one.  

---

## ✨ Features
- 🚀 **Asynchronous scanning** for high-speed enumeration  
- 🔌 **Plugin system** — drop in your own Python plugins for custom checks  
- 🌐 **Subdomain discovery** (integrates with `subfinder` & `amass` if installed)  
- 🔎 **HTTP probing & security header analysis**  
- 🗂 **Common path discovery** (`/admin`, `/login`, `/robots.txt`, etc.)  
- 📸 **Screenshot support** using Playwright  
- 📊 **Reports in JSON, CSV, and HTML** with screenshots embedded  

---

## 📦 Installation

```bash
git clone https://github.com/Vishnu2201/AuditHawk.git
cd AuditHawk
chmod +x install.sh
./install.sh --with-playwright   # installs dependencies + Playwright browsers
```

Activate the environment:
```bash
source .venv/bin/activate
```

---

## 🚀 Usage

### Scan a single target
```bash
python3 AuditHawk.py --target example.com --html report.html --screenshot
```

### Scan multiple targets from a file
```bash
python3 AuditHawk.py --targets hosts.txt --csv results.csv --html report.html
```

### With subdomain enumeration (if tools available)
```bash
python3 AuditHawk.py --target example.com --use-subfinder --output subs.json
```

---

## 📂 Output Examples

- **HTML Report**: interactive, with plugin results + screenshots  
- **CSV**: quick summaries for spreadsheets  
- **JSON**: structured results for scripting  

Example HTML snippet:  
```html
<h2>example.com</h2>
<p>Missing headers: content-security-policy, x-frame-options</p>
<p>Notes: possible admin/login page: https://example.com/admin (403)</p>
```

---

## 🔌 Plugins

AuditHawk comes with built-in plugins:
- **admin_probe** → checks for common admin/login endpoints  
- **cms_fingerprint** → detects CMS files (WordPress, etc.)  
- **s3_probe** → finds exposed AWS S3 buckets  
- **waf_fingerprint** → fingerprints WAF vendors  

You can create your own by adding a `.py` file under `plugins/` with:  

```python
async def run(session, base, results):
    # Your custom logic
    return {"custom": "data"}
```

---

## 🛠 Roadmap
- [ ] Add nuclei template integration  
- [ ] Enhance WAF fingerprinting  
- [ ] Live dashboard mode with WebSocket  
- [ ] More built-in plugins  

---

## ⚡ Quick Start

```bash
# Scan and generate all reports
python3 AuditHawk.py --target target.com --screenshot --html report.html --csv results.csv
```

---

## 📜 License
MIT License © 2025 Vishnu R 
