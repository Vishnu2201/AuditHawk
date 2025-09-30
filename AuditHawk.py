#!/usr/bin/env python3
"""
AuditHawk.py - Async Recon + Pluginable Audit + Screenshots + HTML report

Usage examples:
  python3 AuditHawk.py --target example.com --output out.json --csv out.csv --screenshot --plugins plugins --concurrency 40
  python3 AuditHawk.py --targets hosts.txt --use-subfinder --output multi.json --html report.html

Notes:
 - This tool performs non-invasive checks (HEAD/GET, header analysis, path checks).
 - Plugins must implement: async def run(session, base, results): return plugin_result (dict/None)
 - To enable screenshots, install playwright and run `playwright install`.
"""


import argparse
import asyncio
import importlib.util
import json
import csv
import os
import sys
import subprocess
import glob
import time
from typing import List, Dict, Any
from urllib.parse import urlparse

import aiohttp
import re

# --- Config ---
COMMON_PATHS = [
    "/", "/admin", "/login", "/wp-admin", "/.env", "/robots.txt", "/.git/", "/backup.zip", "/phpinfo.php",
    "/server-status", "/.htaccess"
]
SECURITY_HEADERS = [
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy"
]
DEFAULT_TIMEOUT = 8

# --- Helpers ---
def normalize_target(t: str) -> str:
    t = t.strip()
    if not t:
        return ""
    if t.startswith("http://") or t.startswith("https://"):
        return t
    # prefer https first
    return "https://" + t

def get_host_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc
    except:
        return url

def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    missing = []
    present = {}
    for h in SECURITY_HEADERS:
        if h in headers:
            present[h] = headers[h]
        else:
            missing.append(h)
    return {"present": present, "missing": missing}


# --- HTTP helper functions ---
async def fetch(session: aiohttp.ClientSession, url: str, timeout=DEFAULT_TIMEOUT) -> Dict[str, Any]:
    result = {"url": url, "status": None, "title": None, "server": None, "headers": {}, "len": 0, "error": None}
    try:
        async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
            result["status"] = resp.status
            result["headers"] = {k.lower(): v for k, v in resp.headers.items()}
            result["server"] = resp.headers.get("Server") or resp.headers.get("server")
            text = await resp.text(errors="replace")
            result["len"] = len(text)
            m = re.search(r\"<title>(.*?)</title>\", text, re.IGNORECASE | re.DOTALL)
            if m:
                result["title"] = re.sub(r\"\\s+\", \" \", m.group(1)).strip()
    except Exception as e:
        result[\"error\"] = str(e)
    return result


async def fetch_head_or_get(session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
    out = {\"url\": url, \"status\": None, \"headers\": {}, \"len\": 0, \"error\": None}
    try:
        async with session.head(url, timeout=5, allow_redirects=True) as r:
            out[\"status\"] = r.status
            out[\"headers\"] = {k.lower(): v for k, v in r.headers.items()}
            return out
    except Exception:
        try:
            async with session.get(url, timeout=7, allow_redirects=True) as r2:
                out[\"status\"] = r2.status
                out[\"headers\"] = {k.lower(): v for k, v in r2.headers.items()}
                text = await r2.text(errors=\"replace\")
                out[\"len\"] = len(text)
                return out
        except Exception as e:
            out[\"error\"] = str(e)
            return out


# --- Plugin loader ---
def load_plugins(path: str) -> List[Any]:
    plugins = []
    if not path or not os.path.isdir(path):
        return plugins
    sys.path.insert(0, path)
    for py in sorted(glob.glob(os.path.join(path, \"*.py\"))):
        name = os.path.splitext(os.path.basename(py))[0]
        try:
            spec = importlib.util.spec_from_file_location(name, py)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            if hasattr(mod, \"run\") and asyncio.iscoroutinefunction(mod.run):
                plugins.append((name, mod))
                print(f\"[+] Loaded plugin: {name}\")
            else:
                print(f\"[-] Skipping {name}: missing async run(session, base, results)\")
        except Exception as e:
            print(f\"[-] Error loading plugin {name}: {e}\")
    return plugins


# --- Subdomain discovery helpers (calls external tools if available) ---
def run_subfinder(target: str) -> List[str]:
    try:
        p = subprocess.run([\"subfinder\", \"-d\", target, \"-silent\"], capture_output=True, text=True, timeout=120)
        out = [l.strip() for l in p.stdout.splitlines() if l.strip()]
        print(f\"[subfinder] found {len(out)} domains\")
        return out
    except Exception:
        return []


def run_amass(target: str) -> List[str]:
    try:
        p = subprocess.run([\"amass\", \"enum\", \"-norecursive\", \"-d\", target, \"-o\", \"/dev/stdout\"], capture_output=True, text=True, timeout=240)
        out = [l.strip() for l in p.stdout.splitlines() if l.strip()]
        print(f\"[amass] found {len(out)} domains\")
        return out
    except Exception:
        return []


# --- Screenshots: resilient single-page capture ---
async def take_screenshot(browser, url: str, path: str):
    \"\"\"
    Takes a screenshot for `url` to `path`.
    Primary attempt waits for DOMContentLoaded with 30s timeout.
    Fallback attempt waits for commit (response started) with 10s timeout.
    \"\"\"
    try:
        page = await browser.new_page()
        try:
            await page.set_viewport_size({\"width\": 1280, \"height\": 900})
            # Primary attempt: wait for DOM content loaded
            await page.goto(url, timeout=30000, wait_until=\"domcontentloaded\")
            await page.screenshot(path=path, full_page=True)
            print(f\"[+] Screenshot captured for {url} -> {path}\")
            return True
        except Exception as e:
            print(f\"[!] Primary screenshot attempt failed for {url}: {e}\")
            # Fallback: try faster, stop once response has started
            try:
                await page.goto(url, timeout=10000, wait_until=\"commit\")
                await page.screenshot(path=path, full_page=True)
                print(f\"[+] Fallback screenshot captured for {url} -> {path}\")
                return True
            except Exception as e2:
                print(f\"[-] Screenshot failed completely for {url}: {e2}\")
                return False
        finally:
            try:
                await page.close()
            except Exception:
                pass
    except Exception as outer:
        print(f\"[-] Could not create page for {url}: {outer}\")
        return False


# --- High level audit for a single target ---
async def audit_target(session: aiohttp.ClientSession, base: str, paths: List[str]) -> Dict[str, Any]:
    base = normalize_target(base)
    summary = {\"target\": base, \"host\": get_host_from_url(base), \"http_probe\": None, \"paths\": [], \"sec_headers\": {}, \"notes\": [], \"plugins\": {}}
    probe = await fetch(session, base)
    summary[\"http_probe\"] = probe
    headers = probe.get(\"headers\", {}) or {}
    summary[\"sec_headers\"] = analyze_security_headers(headers)
    # common paths
    tasks = []
    bases = [base]
    if base.startswith(\"https://\"):
        bases.append(\"http://\" + get_host_from_url(base))
    elif base.startswith(\"http://\"):
        bases.append(\"https://\" + get_host_from_url(base))
    for b in bases:
        for p in paths:
            tasks.append(fetch_head_or_get(session, b.rstrip(\"/\") + p))
    if tasks:
        results = await asyncio.gather(*tasks)
        for r in results:
            if r.get(\"status\") and 200 <= r[\"status\"] < 400:
                summary[\"paths\"].append(r)
            elif r.get(\"status\") in (401, 403, 500):
                summary[\"paths\"].append(r)
    # notes: server banner
    if probe.get(\"status\") and probe[\"status\"] < 400:
        if \"x-powered-by\" in headers or \"server\" in headers:
            summary[\"notes\"].append(f\"server banner: {headers.get('server') or headers.get('x-powered-by')}\")
    # detect admin pages and sensitive files
    for p in summary[\"paths\"]:
        if any(x in p[\"url\"].lower() for x in [\"/admin\", \"/wp-admin\", \"/login\"]):
            summary[\"notes\"].append(f\"possible admin/login page: {p['url']} (status {p.get('status')})\")
        if \"/.env\" in p[\"url\"]:
            summary[\"notes\"].append(f\".env file reachable: {p['url']}\")
    return summary


# --- Runner ---
async def run_audit(targets: List[str], concurrency: int, plugins_path: str | None, screenshot_dir: str | None, use_subfinder: bool, output_json: str | None):
    # augment targets via external discovery if requested
    all_targets = []
    for t in targets:
        if use_subfinder:
            all_targets += run_subfinder(t)
            all_targets += run_amass(t)
        all_targets.append(t)
    # dedupe and normalize
    all_targets = sorted({tt.strip() for tt in all_targets if tt.strip()})
    print(f\"[+] Total unique targets: {len(all_targets)}\")


    connector = aiohttp.TCPConnector(limit_per_host=10, ssl=False)
    timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
    plugins = load_plugins(plugins_path) if plugins_path else []
    results: List[Dict[str, Any]] = []

    sem = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async def worker(t):
            async with sem:
                print(f\"[>] Auditing {t}\")
                summary = await audit_target(session, t, COMMON_PATHS)
                # run plugins
                for name, mod in plugins:
                    try:
                        plugin_res = await mod.run(session, t, summary)
                        summary[\"plugins\"][name] = plugin_res
                    except Exception as e:
                        summary[\"plugins\"][name] = {\"error\": str(e)}
                return summary
        tasks = [worker(t) for t in all_targets]
        for fut in asyncio.as_completed(tasks):
            res = await fut
            results.append(res)

    # Take screenshots if requested (best-effort)
    if screenshot_dir:
        try:
            from playwright.async_api import async_playwright
        except Exception as e:
            print(f\"[-] Playwright not available: {e}. Skipping screenshots.\")
            # still continue to write outputs
            if output_json:
                with open(output_json, \"w\", encoding=\"utf-8\") as f:
                    json.dump(results, f, indent=2)
                print(f\"[+] Wrote JSON: {output_json}\")
            return results

        os.makedirs(screenshot_dir, exist_ok=True)
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            for host in all_targets:
                # try https then http primarily (so screenshots prefer secure)
                for scheme in (\"https\", \"http\"):
                    url = f\"{scheme}://{host}\"
                    outfile = os.path.join(screenshot_dir, f\"{host}_{scheme}.png\")
                    try:
                        await take_screenshot(browser, url, outfile)
                    except Exception as e:
                        print(f\"[-] Screenshot failed for {url}: {e}\")
            await browser.close()

    if output_json:
        with open(output_json, \"w\", encoding=\"utf-8\") as f:
            json.dump(results, f, indent=2)
        print(f\"[+] Wrote JSON: {output_json}")

    return results


# --- Reporting helpers ---
def results_to_csv(results: List[Dict[str, Any]], csv_path: str):
    rows = []
    for r in results:
        host = r.get(\"host\")
        status = r.get(\"http_probe\", {}).get(\"status\")
        title = r.get(\"http_probe\", {}).get(\"title\")
        server = r.get(\"http_probe\", {}).get(\"server\")
        sec_missing = \",\".join(r.get(\"sec_headers\", {}).get(\"missing\", []))
        notes = \" | \".join(r.get(\"notes\", []))
        rows.append([host, status, title, server, sec_missing, notes])
    with open(csv_path, \"w\", newline=\"\", encoding=\"utf-8\") as f:
        w = csv.writer(f)
        w.writerow([\"host\", \"status\", \"title\", \"server\", \"missing_security_headers\", \"notes\"])
        w.writerows(rows)
    print(f\"[+] Wrote CSV: {csv_path}\")


def render_html_report(results: List[Dict[str, Any]], html_path: str, screenshots_dir: str | None):
    \"\"\"
    Produce a simple single-file HTML report. Screenshots, if present, are expected
    to be named <host>_https.png and/or <host>_http.png in screenshots_dir.
    \"\"\"
    js_results = json.dumps(results)
    screenshots_dir_js = json.dumps(screenshots_dir or \"\")

    # Use double braces {{ }} where JS/CSS uses braces so .format() won't try to replace them.
    html_template = \"\"\"<!doctype html>
<html>
<head>
<meta charset=\"utf-8\"/>
<title>AuditHawk Report</title>
<style>
body{{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial; margin:20px}}
.card{{border-radius:8px; border:1px solid #ddd; padding:12px; margin-bottom:12px}}
h2{{margin-top:0}}
pre{{background:#f7f7f7;padding:8px;border-radius:6px;overflow:auto}}
.thumb{{max-width:320px;display:block;margin:6px 0;border:1px solid #ccc}}
.screenshot-row{{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}}
.screenshot-row img{{max-width:320px;border-radius:6px;border:1px solid #ccc}}
</style>
</head>
<body>
<h1>AuditHawk Report</h1>
<p>Generated: {ctime}</p>
<div id=\"report\"></div>
<script>
const results = {results};
const screenshotsDir = {screenshots};

function safe(s){{ return (s===null||s===undefined)? \"\": s; }}

const container = document.getElementById('report');
results.forEach(r=>{{
  const div = document.createElement('div'); div.className='card';
  const header = `<h2>${{r.host}} &nbsp; <small>${{safe(r.http_probe && r.http_probe.status)}}</small></h2>`;
  const meta = `<p><strong>Title:</strong> ${{safe(r.http_probe && r.http_probe.title)}} <strong>Server:</strong> ${{safe(r.http_probe && r.http_probe.server)}}</p>`;
  const missing = `<p><strong>Missing security headers:</strong> ${{safe((r.sec_headers && r.sec_headers.missing || []).join(', '))}}</p>`;
  const notes = `<p><strong>Notes:</strong> ${{safe((r.notes||[]).join(' | '))}}</p>`;
  const paths = `<details><summary>Paths (${{(r.paths||[]).length}})</summary><pre>${{JSON.stringify(r.paths, null, 2)}}</pre></details>`;
  const plugins = `<details><summary>Plugin results</summary><pre>${{JSON.stringify(r.plugins, null, 2)}}</pre></details>`;

  div.innerHTML = header + meta + missing + notes + paths + plugins;

  // add screenshots if available
  if (screenshotsDir) {{                                                                
    const row = document.createElement('div'); row.className = 'screenshot-row';
    const host = r.host;
    ['https','http'].forEach(scheme=>{{
      const fn = screenshotsDir + '/' + host + '_' + scheme + '.png';
      const img = document.createElement('img');
      img.src = fn;
      img.alt = host + '_' + scheme;
      row.appendChild(img);
    }});
    div.appendChild(row);
  }}

  container.appendChild(div);
}});
</script>
</body>
</html>
\"\"\".format(
        ctime=time.ctime(),
        results=js_results,
        screenshots=screenshots_dir_js
    )

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_template)
    print(f\"[+] Wrote HTML report: {html_path}\")


# --- CLI ---
def load_targets_from_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return lines


def main():
    parser = argparse.ArgumentParser(description="AuditHawk: async recon + plugin framework + screenshots + report")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--targets", help="file with newline-separated targets (host or domain)")
    group.add_argument("--target", help="single target (example.com)")
    parser.add_argument("--concurrency", type=int, default=40)
    parser.add_argument("--plugins", help="path to plugins folder", default="plugins")
    parser.add_argument("--screenshot", action="store_true", help="take screenshots (requires playwright)")
    parser.add_argument("--screenshot-dir", default="screenshots", help="dir to save screenshots")
    parser.add_argument("--use-subfinder", action="store_true", help="run subfinder/amass if installed to expand targets")
    parser.add_argument("--output", help="JSON output path", default="AuditHawk_results.json")
    parser.add_argument("--csv", help="CSV summary output path", default=None)
    parser.add_argument("--html", help="HTML report path", default=None)
    args = parser.parse_args()

    if args.targets:
        targets = load_targets_from_file(args.targets)
    else:
        targets = [args.target]

    results = asyncio.run(run_audit(targets, concurrency=args.concurrency, plugins_path=args.plugins,
                                    screenshot_dir=(args.screenshot_dir if args.screenshot else None),
                                    use_subfinder=args.use_subfinder, output_json=args.output))

    if args.csv:
        results_to_csv(results, args.csv)
    if args.html:
        render_html_report(results, args.html, args.screenshot_dir if args.screenshot else None)
    else:
        # print a compact summary
        for r in results:
            print(f"-> {r['host']}  status: {r['http_probe'].get('status')}  missing headers: {len(r['sec_headers']['missing'])}  notes: {len(r['notes'])}")


if __name__ == "__main__":
    main()
