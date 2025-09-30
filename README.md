# AuditHawk 🦅

**AuditHawk** is a powerful asynchronous reconnaissance and auditing tool built for bug bounty hunters, penetration testers, and security researchers.  
It automates recon workflows, integrates plugin-based checks, and generates structured **JSON, CSV, and HTML reports** with screenshots.

---

## 🚀 Features
- **Asynchronous scanning** for speed and scale  
- **Plugin-based architecture** – add your own custom checks easily  
- **Screenshot support** using Playwright (with stealth mode)  
- **Subdomain enumeration** via Subfinder & Amass  
- **HTML + CSV + JSON reports** with visual evidence  
- **Security header analysis**  
- **Common path probing** (`/admin`, `/login`, `/robots.txt`, etc.)  
- Lightweight, modular, and extensible  

---

## 📦 Installation

Clone the repository and run the installer:

```bash
git clone https://github.com/<your-username>/AuditHawk.git
cd AuditHawk
chmod +x install.sh
./install.sh --with-playwright
```

> Use `--with-playwright` to install browsers for screenshot support.

Activate the virtual environment:
```bash
source .venv/bin/activate
```

---

## 🛠️ Usage

### Single target:
```bash
python3 AuditHawk.py --target example.com --html report.html --screenshot
```

### Multiple targets from file:
```bash
python3 AuditHawk.py --targets hosts.txt --use-subfinder --csv report.csv
```

### Options:
| Flag               | Description |
|--------------------|-------------|
| `--target`         | Scan a single domain |
| `--targets`        | Load multiple domains from file |
| `--concurrency`    | Number of concurrent requests (default: 40) |
| `--plugins`        | Path to plugins (default: `plugins/`) |
| `--screenshot`     | Enable screenshots |
| `--screenshot-dir` | Directory to save screenshots (default: `screenshots/`) |
| `--use-subfinder`  | Run subfinder + amass for subdomains |
| `--output`         | Save results in JSON format |
| `--csv`            | Save results in CSV format |
| `--html`           | Save results in HTML report |
| `--delay`          | Delay between requests |
| `--stealth`        | Enable stealth mode for Playwright |

---

## 📂 Plugins

Plugins live in the `plugins/` directory.  
Each plugin must define:

```python
async def run(session, base, results):
    return {"key": "value"}
```

### Included plugins:
- `admin_probe.py` – looks for common admin panels  
- `cms_fingerprint.py` – fingerprints common CMS technologies  
- `s3_probe.py` – checks for misconfigured S3 buckets  
- `waf_fingerprint.py` – detects Web Application Firewalls  

---

## 📊 Example Output

Run against `flipkart.com`:
- JSON: `AuditHawk_results.json`  
- CSV: `report.csv`  
- HTML: `report.html` with screenshots  

---

## 📝 License
MIT License – free to use and modify.

---

## 💡 Contributing
PRs and new plugins are welcome!  

---

## ⚠️ Disclaimer
AuditHawk is built for **educational and authorized security testing purposes only**.  
The author is **not responsible for misuse** of this tool.
