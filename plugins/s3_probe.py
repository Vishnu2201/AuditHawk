import asyncio
from urllib.parse import urlparse
async def run(session, base, results):
    host = results.get("host") or urlparse(base).netloc
    COMMON_SUFFIXES = ["-backup", "-files", "-static", "-assets", "assets", "static"]
    candidates = [host] + [host + s for s in COMMON_SUFFIXES]
    found = []
    for c in candidates:
        urls = [f"https://{c}.s3.amazonaws.com/", f"https://s3.amazonaws.com/{c}/"]
        for u in urls:
            try:
                async with session.head(u, timeout=5, allow_redirects=True) as r:
                    if r.status < 400:
                        found.append({"bucket": c, "url": u, "status": r.status})
                    elif r.status in (401,403):
                        found.append({"bucket": c, "url": u, "status": r.status})
            except Exception:
                pass
    return {"s3_buckets": found}
