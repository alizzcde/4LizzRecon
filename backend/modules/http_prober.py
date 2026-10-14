"""
Real Async HTTP Prober
Probes resolved hosts, extracts HTTP status codes, titles, headers, and identifies categories/risks.
"""

import re
import asyncio
from typing import Dict, List, Optional, Callable, Awaitable
import httpx

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
PROBE_TIMEOUT = 5.0

def extract_title(html: str) -> str:
    match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if match:
        clean = re.sub(r'\s+', ' ', match.group(1)).strip()
        return clean[:100]
    return ""

def classify_category_and_risk(host: str, status: int, title: str, server: str, final_url: str) -> tuple[str, str]:
    text = f"{host} {title} {server} {final_url}".lower()

    # Category classification
    if any(k in text for k in ['login', 'signin', 'auth', 'sso', 'oauth', 'saml']):
        category = "LOGIN"
    elif any(k in text for k in ['api', 'graphql', 'swagger', 'v1', 'v2', 'endpoint']):
        category = "API"
    elif any(k in text for k in ['admin', 'manager', 'dashboard', 'internal', 'console', 'panel']):
        category = "ADMIN"
    elif any(k in text for k in ['vpn', 'gateway', 'citrix', 'pulse', 'cisco']):
        category = "VPN"
    elif any(k in text for k in ['portal', 'account', 'customer', 'member']):
        category = "PORTAL"
    elif any(k in text for k in ['azure', 'aws', 'cloudflare', 'fastly', 'akamai', 'cloudfront']):
        category = "CDN/CLOUD"
    else:
        category = "WEB"

    # Risk heuristic
    if status >= 500:
        risk = "CRITICAL"
    elif status == 403 and any(k in text for k in ['admin', 'internal', 'config', 'backup', 'db', 'portal']):
        risk = "HIGH"
    elif status == 200 and any(k in text for k in ['admin', 'internal', 'staging', 'dev', 'test']):
        risk = "HIGH"
    elif status == 200 and category in ['LOGIN', 'VPN', 'API']:
        risk = "MED"
    elif status == 200:
        risk = "LOW"
    elif 300 <= status < 400:
        risk = "INFO"
    else:
        risk = "INFO"

    return category, risk

async def probe_single_host(
    client: httpx.AsyncClient,
    host_info: Dict,
    sem: asyncio.Semaphore
) -> Optional[Dict]:
    """
    Probe a host first over HTTPS, then fallback to HTTP.
    """
    host = host_info["subdomain"]
    ip = host_info.get("ip")

    async with sem:
        for proto in ["https", "http"]:
            target_url = f"{proto}://{host}"
            try:
                resp = await client.get(
                    target_url,
                    timeout=PROBE_TIMEOUT,
                    follow_redirects=True
                )
                status = resp.status_code
                final_url = str(resp.url)
                server = resp.headers.get("server", "")
                title = extract_title(resp.text)
                category, risk = classify_category_and_risk(host, status, title, server, final_url)

                return {
                    "subdomain": host,
                    "status": status,
                    "title": title,
                    "server": server,
                    "category": category,
                    "risk": risk,
                    "ip": ip or "",
                    "finalUrl": final_url
                }
            except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError, httpx.HTTPError):
                continue
            except Exception:
                continue

    return None

async def run_http_prober(
    hosts: List[Dict],
    concurrency: int = 30,
    on_live_found: Optional[Callable[[Dict], Awaitable[None]]] = None
) -> List[Dict]:
    """
    Runs asynchronous HTTP probing over a list of resolved hosts.
    """
    sem = asyncio.Semaphore(concurrency)
    live_results = []
    headers = {"User-Agent": USER_AGENT}

    async with httpx.AsyncClient(headers=headers, verify=False) as client:
        tasks = []
        for h in hosts:
            async def _worker(host_info=h):
                res = await probe_single_host(client, host_info, sem)
                if res:
                    live_results.append(res)
                    if on_live_found:
                        await on_live_found(res)
                return res

            tasks.append(_worker())

        await asyncio.gather(*tasks, return_exceptions=True)

    return live_results
