# plugins/cms_fingerprint.py
# Simple CMS fingerprint plugin - looks for common CMS fingerprints in headers/title

import re

async def run(session, base, results):
    # results is the current summary; we return dict with findings
    probe = results.get("http_probe", {}) or {}
    title = (probe.get("title") or "").lower()
    headers = probe.get("headers") or {}
    findings = []
    # title heuristics
    if "wordpress" in title or "wp-" in (probe.get("url","") or ""):
        findings.append("wordpress (title heur)")
    # headers
    server = headers.get("server","").lower()
    if "nginx" in server:
        findings.append("server: nginx")
    # common paths
    for p in results.get("paths", []):
        u = p.get("url","").lower()
        if "/wp-" in u:
            findings.append("wordpress files detected: " + u)
        if "/sites/default" in u:
            findings.append("possible drupal")
    return {"fingerprints": list(set(findings))}
