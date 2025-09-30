#!/usr/bin/env python3
"""
AuditHawk.py - Async Recon + Pluginable Audit + Screenshots + HTML report
with stealth, retry, and randomization support.

Usage examples:
  python3 AuditHawk.py --target example.com --output out.json --csv out.csv --screenshot --plugins plugins --concurrency 40
  python3 AuditHawk.py --targets hosts.txt --use-subfinder --output multi.json --html report.html --stealth

Notes:
 - Non-invasive checks (HEAD/GET, header analysis, path checks).
 - Plugins must implement: async def run(session, base, results): return plugin_result (dict/None).
 - For screenshots, install playwright: `pip install playwright playwright-stealth` and run `playwright install`.
"""

import argparse, asyncio, importlib.util, json, csv, os, sys, subprocess, glob, time, random, re
from typing import List, Dict, Any
from urllib.parse import urlparse

import aiohttp
from aiohttp.client_exceptions import ClientError
try:
    from fake_useragent import UserAgent
    UA = UserAgent()
    def random_ua(): return UA.random
except Exception:
    FALLBACK_UAS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; rv:126.0) Gecko/20100101 Firefox/126.0"
    ]
    def random_ua(): return random.choice(FALLBACK_UAS)

# --- Config ---
COMMON_PATHS = ["/", "/admin", "/login", "/wp-admin", "/.env", "/robots.txt",
                "/.git/", "/backup.zip", "/phpinfo.php", "/server-status", "/.htaccess"]
SECURITY_HEADERS = ["content-security-policy", "strict-transport-security",
    "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"]
DEFAULT_TIMEOUT = 8

# --- Helpers ---
def normalize_target(t: str) -> str:
    t = t.strip()
    if not t: return ""
    return t if t.startswith("http") else "https://" + t

def get_host_from_url(url: str) -> str:
    try: return urlparse(url).netloc
    except: return url

def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    missing, present = [], {}
    for h in SECURITY_HEADERS:
        if h in headers: present[h] = headers[h]
        else: missing.append(h)
    return {"present": present, "missing": missing}

# --- HTTP helper ---
async def fetch(session, url: str, timeout=DEFAULT_TIMEOUT, retries=2, delay=0) -> Dict[str, Any]:
    result = {"url": url, "status": None, "title": None, "server": None, "headers": {}, "len": 0, "error": None}
    for attempt in range(retries+1):
        headers = {"User-Agent": random_ua(), "Accept": "text/html", "Accept-Language": "en-US,en;q=0.9"}
        try:
            async with session.get(url, headers=headers, timeout=timeout, allow_redirects=True) as resp:
                result["status"] = resp.status
                result["headers"] = {k.lower(): v for k,v in resp.headers.items()}
                result["server"] = resp.headers.get("Server")
                text = await resp.text(errors="replace")
                result["len"] = len(text)
                m = re.search(r"<title>(.*?)</title>", text, re.I|re.S)
                if m: result["title"] = re.sub(r"\s+"," ",m.group(1)).strip()
                return result
        except Exception as e:
            result["error"] = str(e)
            if attempt<retries: await asyncio.sleep(1+attempt)
    return result

async def fetch_head_or_get(session, url: str) -> Dict[str, Any]:
    out = {"url": url, "status": None, "headers": {}, "len": 0, "error": None}
    try:
        async with session.head(url, timeout=5, allow_redirects=True) as r:
            out["status"], out["headers"] = r.status, {k.lower(): v for k,v in r.headers.items()}
            return out
    except Exception:
        try:
            async with session.get(url, timeout=7, allow_redirects=True) as r2:
                out["status"], out["headers"] = r2.status, {k.lower(): v for k,v in r2.headers.items()}
                text = await r2.text(errors="replace"); out["len"]=len(text)
                return out
        except Exception as e: out["error"]=str(e); return out

# --- Plugin loader ---
def load_plugins(path: str) -> List[Any]:
    plugins=[]
    if not path or not os.path.isdir(path): return plugins
    sys.path.insert(0,path)
    for py in sorted(glob.glob(os.path.join(path,"*.py"))):
        name=os.path.splitext(os.path.basename(py))[0]
        try:
            spec=importlib.util.spec_from_file_location(name,py)
            mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
            if hasattr(mod,"run") and asyncio.iscoroutinefunction(mod.run):
                plugins.append((name,mod)); print(f"[+] Loaded plugin: {name}")
            else: print(f"[-] Skipping {name}: no async run()")
        except Exception as e: print(f"[-] Error loading {name}: {e}")
    return plugins

# --- Subdomain discovery ---
def run_subfinder(target): 
    try:
        p=subprocess.run(["subfinder","-d",target,"-silent"],capture_output=True,text=True,timeout=120)
        return [l.strip() for l in p.stdout.splitlines() if l.strip()]
    except: return []
def run_amass(target): 
    try:
        p=subprocess.run(["amass","enum","-norecursive","-d",target,"-o","/dev/stdout"],capture_output=True,text=True,timeout=240)
        return [l.strip() for l in p.stdout.splitlines() if l.strip()]
    except: return []

# --- Screenshot ---
async def take_screenshot(browser, url, path, stealth=False):
    try:
        page=await browser.new_page()
        if stealth:
            try: from playwright_stealth import stealth_async; await stealth_async(page)
            except: pass
        await page.set_viewport_size({"width":1280,"height":900})
        await page.set_extra_http_headers({"User-Agent": random_ua(), "Referer":"https://www.google.com/"})
        await page.goto(url,timeout=30000,wait_until="domcontentloaded")
        await asyncio.sleep(random.uniform(2,5))
        await page.screenshot(path=path,full_page=True)
        print(f"[+] Screenshot {url} -> {path}")
        await page.close(); return True
    except Exception as e: print(f"[-] Screenshot failed for {url}: {e}"); return False

# --- Audit one target ---
async def audit_target(session, base, paths: List[str], delay:int) -> Dict[str,Any]:
    base=normalize_target(base)
    summary={"target":base,"host":get_host_from_url(base),"http_probe":None,"paths":[],"sec_headers":{},"notes":[],"plugins":{}}
    summary["http_probe"]=await fetch(session,base,delay=delay)
    headers=summary["http_probe"].get("headers",{}) or {}
    summary["sec_headers"]=analyze_security_headers(headers)
    tasks=[]
    for b in [base.replace("https://","http://") if base.startswith("https") else "https://"+get_host_from_url(base), base]:
        for p in paths: tasks.append(fetch_head_or_get(session,b.rstrip("/")+p))
    if tasks:
        results=await asyncio.gather(*tasks)
        for r in results:
            if r.get("status") and r["status"]<400: summary["paths"].append(r)
            elif r.get("status") in (401,403,500): summary["paths"].append(r)
    if "server" in headers: summary["notes"].append(f"server banner: {headers.get('server')}")
    for p in summary["paths"]:
        if any(x in p["url"].lower() for x in ["/admin","/wp-admin","/login"]):
            summary["notes"].append(f"possible admin/login page: {p['url']} ({p.get('status')})")
        if "/.env" in p["url"]: summary["notes"].append(f".env file reachable: {p['url']}")
    if delay: await asyncio.sleep(delay)
    return summary

# --- Runner ---
async def run_audit(targets:List[str], concurrency:int, plugins_path:str|None, screenshot_dir:str|None,
                    use_subfinder:bool, output_json:str|None, delay:int, stealth:bool):
    all_targets=[]
    for t in targets:
        if use_subfinder: all_targets+=run_subfinder(t)+run_amass(t)
        all_targets.append(t)
    all_targets=sorted({tt.strip() for tt in all_targets if tt.strip()})
    print(f"[+] Total unique targets: {len(all_targets)}")
    connector=aiohttp.TCPConnector(limit_per_host=10,ssl=False)
    timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
    plugins=load_plugins(plugins_path) if plugins_path else []
    results=[]
    sem=asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession(connector=connector,timeout=timeout) as session:
        async def worker(t):
            async with sem:
                print(f"[>] Auditing {t}")
                s=await audit_target(session,t,COMMON_PATHS,delay)
                for name,mod in plugins:
                    try: s["plugins"][name]=await mod.run(session,t,s)
                    except Exception as e: s["plugins"][name]={"error":str(e)}
                return s
        tasks=[worker(t) for t in all_targets]
        for fut in asyncio.as_completed(tasks): results.append(await fut)

    if screenshot_dir:
        try: from playwright.async_api import async_playwright
        except: print("[-] Playwright not installed"); return results
        os.makedirs(screenshot_dir,exist_ok=True)
        async with async_playwright() as pw:
            browser=await pw.chromium.launch(headless=True)
            for host in all_targets:
                for scheme in ("https","http"):
                    await take_screenshot(browser,f"{scheme}://{host}",
                        os.path.join(screenshot_dir,f"{host}_{scheme}.png"),stealth=stealth)
            await browser.close()

    if output_json:
        with open(output_json,"w",encoding="utf-8") as f: json.dump(results,f,indent=2)
        print(f"[+] Wrote JSON: {output_json}")
    return results

# --- Reporting ---
def render_html_report(results, html_path, screenshots_dir: str | None):
    """
    Generate a self-contained HTML report.
    """
    js_results = json.dumps(results)
    screenshots_dir_js = json.dumps(screenshots_dir or "")

    html_template = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>AuditHawk Report</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 20px; }}
.card {{ border: 1px solid #ddd; padding: 12px; margin: 12px 0; border-radius: 8px; }}
.card h2 {{ margin: 0 0 8px; }}
pre {{ background: #f7f7f7; padding: 8px; border-radius: 6px; overflow: auto; }}
img.thumb {{ max-width: 320px; margin: 6px 4px; border: 1px solid #ccc; border-radius: 6px; }}
.screenshot-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }}
</style>
</head>
<body>
<h1>AuditHawk Report</h1>
<p>Generated: {time.ctime()}</p>
<div id="report"></div>
<script>
const results = {js_results};
const screenshotsDir = {screenshots_dir_js};

function safe(s) {{ return (s===null || s===undefined) ? "" : s; }}

const container = document.getElementById('report');
results.forEach(r => {{
  const div = document.createElement('div');
  div.className = 'card';
  div.innerHTML = `
    <h2>${{r.host}} <small>(${ { " " } }safe(r.http_probe && r.http_probe.status))</small></h2>
    <p><b>Title:</b> ${{safe(r.http_probe && r.http_probe.title)}} 
       <b>Server:</b> ${{safe(r.http_probe && r.http_probe.server)}}</p>
    <p><b>Missing headers:</b> ${{safe((r.sec_headers && r.sec_headers.missing || []).join(', '))}}</p>
    <p><b>Notes:</b> ${{safe((r.notes || []).join(' | '))}}</p>
    <details><summary>Paths (${{(r.paths || []).length}})</summary>
      <pre>${{JSON.stringify(r.paths, null, 2)}}</pre>
    </details>
    <details><summary>Plugins</summary>
      <pre>${{JSON.stringify(r.plugins, null, 2)}}</pre>
    </details>
  `;

  if (screenshotsDir) {{
    const row = document.createElement('div');
    row.className = 'screenshot-row';
    ["https","http"].forEach(sch => {{
      const img = document.createElement('img');
      img.src = screenshotsDir + "/" + r.host + "_" + sch + ".png";
      img.className = 'thumb';
      img.alt = r.host + "_" + sch;
      row.appendChild(img);
    }});
    div.appendChild(row);
  }}
  container.appendChild(div);
}});
</script>
</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_template)
    print(f"[+] Wrote HTML report: {html_path}")



# --- CLI ---
def load_targets_from_file(path): 
    return [l.strip() for l in open(path) if l.strip() and not l.startswith("#")]

# --- Reporting ---
def results_to_csv(results: List[Dict[str, Any]], csv_path: str):
    rows = []
    for r in results:
        host = r.get("host")
        status = r.get("http_probe", {}).get("status")
        title = r.get("http_probe", {}).get("title")
        server = r.get("http_probe", {}).get("server")
        sec_missing = ",".join(r.get("sec_headers", {}).get("missing", []))
        notes = " | ".join(r.get("notes", []))
        rows.append([host, status, title, server, sec_missing, notes])
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "status", "title", "server", "missing_security_headers", "notes"])
        w.writerows(rows)
    print(f"[+] Wrote CSV: {csv_path}")


def render_html_report(results, html_path, screenshots_dir: str | None):
    ...
    # (your f-string HTML template, unchanged except no stray `d`)


def main():
    p=argparse.ArgumentParser(description="AuditHawk async recon tool")
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--targets",help="file with targets"); g.add_argument("--target",help="single target")
    p.add_argument("--concurrency",type=int,default=40)
    p.add_argument("--plugins",default="plugins"); p.add_argument("--screenshot",action="store_true")
    p.add_argument("--screenshot-dir",default="screenshots"); p.add_argument("--use-subfinder",action="store_true")
    p.add_argument("--output",default="AuditHawk_results.json"); p.add_argument("--csv"); p.add_argument("--html")
    p.add_argument("--delay",type=int,default=0,help="delay between requests (sec)")
    p.add_argument("--stealth",action="store_true",help="enable stealth mode for screenshots")
    a=p.parse_args()
    targets=load_targets_from_file(a.targets) if a.targets else [a.target]
    res=asyncio.run(run_audit(targets,a.concurrency,a.plugins,a.screenshot_dir if a.screenshot else None,
        a.use_subfinder,a.output,a.delay,a.stealth))
    if a.csv:
        results_to_csv(res, a.csv)

    if a.html:
        render_html_report(res, a.html, a.screenshot_dir if a.screenshot else None)

    if not a.html and not a.csv:
        for r in res:
            print(f"-> {r['host']} {r['http_probe'].get('status')} "
                f"headers missing:{len(r['sec_headers']['missing'])}")


if __name__=="__main__": main()
