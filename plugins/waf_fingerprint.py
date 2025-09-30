import re
async def run(session, base, results):
    WAF_SIGNATURES = {
        "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "body": [r"cloudflare", r"attention required!"]},
        "Akamai": {"headers": ["akamai-ghost"], "body": [r"akamai"]},
        "DataDome": {"headers": ["x-datadome", "datadome"], "body": [r"datadome"]},
        "Imperva": {"headers": ["incap-req-id", "visid_incap"], "body": [r"incapsula", r"imperva"]},
        "Sucuri": {"headers": ["x-sucuri-id"], "body": [r"sucuri web firewall"]},
    }
    findings = []
    for entry in results.get("paths", []):
        headers = {k.lower(): v for k, v in entry.get("headers", {}).items()}
        for waf, sigs in WAF_SIGNATURES.items():
            if any(h in headers for h in sigs["headers"]):
                findings.append(f"{waf} detected via headers: {list(headers.keys())}")
    return {"waf": list(set(findings))}
