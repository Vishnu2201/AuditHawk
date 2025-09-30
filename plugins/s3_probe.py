# plugins/s3_probe.py
# Checks common S3 bucket name patterns derived from host and a few common variants.
import aiohttp
import asyncio
from urllib.parse import urlparse

COMMON_SUFFIXES = ["-backup", "-files", "-static", "-assets", "assets", "static"]

async def run(session, base, results):
    host = results.get("host") or urlparse(base).netloc
    candidates = [host] + [host + s for s in COMMON_SUFFIXES]
    found = []
    for c in candidates:
        # try common Amazon S3 patterns
        urls = [
            f"https://{c}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{c}/"
        ]
        for u in urls:
            try:
                async with session.head(u, timeout=5, allow_redirects=True) as r:
                    if r.status < 400:
                        found.append({"bucket": c, "url": u, "status": r.status})
                    elif r.status in (403, 401):
                        # bucket exists but restricted
                        found.append({"bucket": c, "url": u, "status": r.status})
            except Exception:
                pass
    if found:
        return {"s3_buckets": found}
    return {"s3_buckets": []}
