from typing import Dict, Any
import re

# Simple header/body-based WAF detection
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status"],
        "body": [r"cloudflare", r"attention required!"]
    },
    "Akamai": {
        "headers": ["akamai-ghost", "akamai-grn"],
        "body": [r"akamai", r"akamaiGHost"]
    },
    "DataDome": {
        "headers": ["x-datadome", "datadome"],
        "body": [r"datadome", r"protected by datadome"]
    },
    "Imperva / Incapsula": {
        "headers": ["incap-req-id", "visid_incap"],
        "body": [r"incapsula", r"imperva"]
    },
    "Sucuri": {
        "headers": ["x-sucuri-id"],
        "body": [r"sucuri web firewall"]
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-waf-event"],
        "body": [r"the requested url was rejected"]
    },
}

async def run(session, base: str, results: Dict[str, Any]):
    findings = []
    for entry in results.get("paths", []):
        headers = {k.lower(): v for k, v in entry.get("headers", {}).items()}
        body_sample = ""  # (Not fetching body for now, but could extend)

        for waf, sigs in WAF_SIGNATURES.items():
            if any(h in headers for h in sigs["headers"]):
                findings.append(f"{waf} detected via headers: {list(headers.keys())}")
            for pattern in sigs["body"]:
                if re.search(pattern, body_sample, re.I):
                    findings.append(f"{waf} detected via body match '{pattern}'")

    return {"waf": list(set(findings))}
