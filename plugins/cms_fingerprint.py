import re
async def run(session, base, results):
    probe = results.get("http_probe", {}) or {}
    title = (probe.get("title") or "").lower()
    headers = probe.get("headers") or {}
    findings = []
    if "wordpress" in title or "wp-" in (probe.get("url","") or ""):
        findings.append("wordpress (title heur)")
    server = headers.get("server","").lower() if headers.get("server") else ""
    if "nginx" in server:
        findings.append("server: nginx")
    for p in results.get("paths", []):
        u = p.get("url","").lower()
        if "/wp-" in u:
            findings.append("wordpress files detected: " + u)
        if "/sites/default" in u:
            findings.append("possible drupal")
    return {"fingerprints": list(set(findings))}
