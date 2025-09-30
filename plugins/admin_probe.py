# plugins/admin_probe.py
# Non-destructive admin probe - checks a short list of additional admin-like paths (no brute force)
import asyncio

EXTRA = ["/administrator/", "/admin.php", "/wp-login.php", "/user/login", "/dash", "/manage"]

async def run(session, base, results):
    bases = [base]
    if base.startswith("https://"):
        bases.append("http://" + results.get("host"))
    else:
        bases.append("https://" + results.get("host"))
    found = []
    for b in bases:
        for p in EXTRA:
            url = b.rstrip("/") + p
            try:
                async with session.head(url, timeout=4, allow_redirects=True) as r:
                    if r.status < 400 or r.status in (401, 403):
                        found.append({"url": url, "status": r.status})
            except Exception:
                pass
    return {"admin_candidates": found}
