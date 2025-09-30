# AuditHawk 🔍
Async Recon + Pluginable Pentesting Helper

Pentool is a **safe, non-destructive recon tool** for penetration testers.
It discovers subdomains, probes HTTP(S), checks headers, finds common paths, runs plugins, and can generate screenshots & HTML reports.

---

## Features
- 🌐 Subdomain discovery (via `subfinder` / `amass` if installed)
- ⚡ Async HTTP probing (fast, concurrent)
- 🧩 Plugin system (drop in `plugins/*.py`)
- 📋 Security header audit
- 🔍 Common file/path checks (`/.env`, `/admin`, `/login`, etc.)
- 🖼 Screenshots via Playwright (optional)
- 📊 JSON, CSV, and HTML reporting

---

## Installation

Clone the repo:
```bash
git clone https://github.com/yourusername/pentool.git
cd pentool
```

Run installer:
```bash
./install.sh
```

If you want screenshots:
```bash
./install.sh --with-playwright
```

Activate environment:
```bash
source .venv/bin/activate
```

---

## Usage

Single target:
```bash
python3 pentool.py --target example.com --output results.json --csv summary.csv --plugins plugins
```

Multiple targets:
```bash
python3 pentool.py --targets examples/hosts.txt --use-subfinder --screenshot --plugins plugins --output results.json --csv summary.csv --html report.html
```

Help:
```bash
python3 pentool.py --help
```

---

## Plugins

Three example plugins are included in `plugins/`:
- `cms_fingerprint.py` → detects WordPress/Drupal
- `s3_probe.py` → checks for open or restricted S3 buckets
- `admin_probe.py` → finds common admin portals

You can create your own by adding files to `plugins/` with:
```python
async def run(session, base, results):
    # return dict of findings
```

---

## Output
- `results.json` → full structured data
- `summary.csv` → compact summary for spreadsheets
- `report.html` → interactive HTML report with screenshots

---

## Example
```bash
python3 pentool.py --target example.com --screenshot --html report.html
```

Produces:

- JSON with detailed results
- CSV with summary
- HTML report with screenshots embedded

---

## Legal Disclaimer
This tool is for **educational and authorized security testing only**.
Do not use against systems without explicit written permission.
The author is not responsible for misuse.
