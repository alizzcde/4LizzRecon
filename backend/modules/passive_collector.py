"""
Real Passive OSINT Collectors with authenticated services (Shodan, VirusTotal, GitHub, etc.)
and robust error reporting.
"""

import re
import json
import os
import asyncio
import httpx
from typing import Set, Dict, Callable, Awaitable

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
TIMEOUT = 14.0

def clean_subdomain(sub: str, domain: str) -> str:
    """Strictly cleans, normalizes and validates a subdomain against the root domain"""
    if not sub:
        return ""
    sub = sub.strip().lower()
    sub = re.sub(r'^\*\.', '', sub)
    sub = re.sub(r'^https?://', '', sub)
    sub = sub.split('/')[0].split(':')[0]
    
    # Must end with root domain
    if sub.endswith('.' + domain) or sub == domain:
        # Strict RFC 1123 domain validation (no HTML, quotes, escaped chars)
        if re.match(r'^[a-z0-9]([a-z0-9\-_]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]{0,61}[a-z0-9])?)*$', sub):
            return sub
    return ""

def load_api_keys() -> Dict[str, str]:
    """Loads API keys from config.json"""
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

# --- Shodan ---
async def fetch_shodan(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    key = keys.get("shodan_api_key", "").strip()
    if not key:
        return set()
    subs = set()
    url = f"https://api.shodan.io/dns/domain/{domain}?key={key}"
    try:
        resp = await client.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for sub_prefix in data.get("subdomains", []):
                full_sub = f"{sub_prefix}.{domain}"
                cleaned = clean_subdomain(full_sub, domain)
                if cleaned:
                    subs.add(cleaned)
        elif resp.status_code == 401:
            await log("[shodan] API açarı etibarsızdır (401 Unauthorized)", "dim")
        else:
            await log(f"[shodan] Cavab: {resp.status_code}", "dim")
    except Exception as e:
        await log(f"[shodan] Xəta: {str(e)}", "dim")
    return subs

# --- VirusTotal ---
async def fetch_virustotal(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    key = keys.get("virustotal_api_key", "").strip()
    if not key:
        return set()
    subs = set()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    headers = {"x-apikey": key}
    try:
        resp = await client.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("data", []):
                sub = item.get("id", "")
                cleaned = clean_subdomain(sub, domain)
                if cleaned:
                    subs.add(cleaned)
        elif resp.status_code == 401:
            await log("[virustotal] API açarı icazəsizdir (401)", "dim")
    except Exception as e:
        await log(f"[virustotal] Xəta: {str(e)}", "dim")
    return subs

# --- GitHub ---
async def fetch_github(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    token = keys.get("github_token", "").strip()
    if not token:
        return set()
    subs = set()
    url = f"https://api.github.com/search/code?q={domain}&per_page=30"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    try:
        resp = await client.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("items", []):
                text = f"{item.get('name', '')} {item.get('path', '')}"
                found = re.findall(rf'([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})', text)
                for f in found:
                    cleaned = clean_subdomain(f, domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception as e:
        pass
    return subs

# --- ZoomEye ---
async def fetch_zoomeye(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    key = keys.get("zoomeye_api_key", "").strip()
    if not key:
        return set()
    subs = set()
    # Try api.zoomeye.org
    try:
        url = f"https://api.zoomeye.org/domain/search?q={domain}&type=1"
        resp = await client.get(url, headers={"API-KEY": key}, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("list", []):
                cleaned = clean_subdomain(item.get("name", ""), domain)
                if cleaned:
                    subs.add(cleaned)
        elif resp.status_code == 403:
            await log("[zoomeye] ZoomEye: 'this service not available in your area' (Bölgesel kısıtlama)", "wildcard")
    except Exception as e:
        await log(f"[zoomeye] Bağlantı hatası: {str(e)}", "dim")
    return subs

# --- SecurityTrails ---
async def fetch_securitytrails(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    key = keys.get("securitytrails_api_key", "").strip()
    if not key:
        return set()
    subs = set()
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": key, "Accept": "application/json"}
    try:
        resp = await client.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for sub_prefix in data.get("subdomains", []):
                full_sub = f"{sub_prefix}.{domain}"
                cleaned = clean_subdomain(full_sub, domain)
                if cleaned:
                    subs.add(cleaned)
        elif resp.status_code == 401 or resp.status_code == 403:
            await log("[securitytrails] API anahtarı geçersiz (401/403)", "dim")
    except Exception as e:
        await log(f"[securitytrails] Hata: {str(e)}", "dim")
    return subs

# --- Chaos ---
async def fetch_chaos(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    key = keys.get("chaos_api_key", "").strip()
    if not key:
        return set()
    subs = set()
    url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
    headers = {"Authorization": key}
    try:
        resp = await client.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for sub_prefix in data.get("subdomains", []):
                full_sub = f"{sub_prefix}.{domain}"
                cleaned = clean_subdomain(full_sub, domain)
                if cleaned:
                    subs.add(cleaned)
        elif resp.status_code == 401:
            await log("[chaos] ProjectDiscovery Cloud token gerektiriyor (401)", "dim")
    except Exception as e:
        pass
    return subs

# --- Free Public Sources ---

async def fetch_crtsh(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    subs = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = await client.get(url, timeout=25.0)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                for line in entry.get("name_value", "").split("\n"):
                    cleaned = clean_subdomain(line, domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception:
        pass
    return subs

async def fetch_alienvault(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    subs = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        resp = await client.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for record in data.get("passive_dns", []):
                cleaned = clean_subdomain(record.get("hostname", ""), domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception:
        pass
    return subs

async def fetch_hackertarget(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    subs = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        resp = await client.get(url, timeout=TIMEOUT)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.splitlines():
                if "," in line:
                    cleaned = clean_subdomain(line.split(",")[0], domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception:
        pass
    return subs

async def fetch_anubis(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    subs = set()
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    try:
        resp = await client.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for item in data:
                    cleaned = clean_subdomain(item, domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception:
        pass
    return subs

async def fetch_threatminer(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    subs = set()
    url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
    try:
        resp = await client.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("results", []):
                cleaned = clean_subdomain(item, domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception:
        pass
    return subs

async def fetch_wayback(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    subs = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original"
    try:
        resp = await client.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for row in data[1:]:
                if row and isinstance(row, list) and len(row) > 0:
                    cleaned = clean_subdomain(row[0], domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception:
        pass
    return subs

async def fetch_certspotter(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    subs = set()
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        resp = await client.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for item in data:
                for dns_name in item.get("dns_names", []):
                    cleaned = clean_subdomain(dns_name, domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception:
        pass
    return subs

async def fetch_rapiddns(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    subs = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        resp = await client.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            for m in re.findall(rf'([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})', resp.text):
                cleaned = clean_subdomain(m, domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception:
        pass
    return subs

async def fetch_urlscan(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    subs = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
    try:
        resp = await client.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for r in data.get("results", []):
                p_domain = r.get("page", {}).get("domain", "")
                cleaned = clean_subdomain(p_domain, domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception:
        pass
    return subs

async def fetch_jldc(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    subs = set()
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    try:
        resp = await client.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for item in data:
                    cleaned = clean_subdomain(item, domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception:
        pass
    return subs

async def fetch_subdomaincenter(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    subs = set()
    url = f"https://api.subdomain.center/subdomains?domain={domain}"
    try:
        resp = await client.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for item in data:
                    cleaned = clean_subdomain(item, domain)
                    if cleaned:
                        subs.add(cleaned)
    except Exception:
        pass
    return subs

async def fetch_robtex(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    subs = set()
    url = f"https://freeapi.robtex.com/pdns/forward/{domain}"
    try:
        resp = await client.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                try:
                    obj = json.loads(line)
                    rrname = obj.get("rrname", "")
                    cleaned = clean_subdomain(rrname, domain)
                    if cleaned:
                        subs.add(cleaned)
                except Exception:
                    pass
    except Exception:
        pass
    return subs

async def fetch_leakix(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    subs = set()
    url = f"https://leakix.net/search?scope=leak&q={domain}"
    try:
        resp = await client.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            for m in re.findall(rf'([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})', resp.text):
                cleaned = clean_subdomain(m, domain)
                if cleaned:
                    subs.add(cleaned)
    except Exception:
        pass
    return subs

async def fetch_fofa(client: httpx.AsyncClient, domain: str, keys: dict, log: Callable) -> Set[str]:
    key = keys.get("fofa_api_key", "").strip()
    subs = set()
    if key:
        import base64
        qbase64 = base64.b64encode(f'domain="{domain}"'.encode()).decode()
        url = f"https://fofa.info/api/v1/search/all?email={keys.get('fofa_email', '')}&key={key}&qbase64={qbase64}&size=100"
        try:
            resp = await client.get(url, timeout=TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("results", []):
                    host_str = item[0] if isinstance(item, list) else str(item)
                    cleaned = clean_subdomain(host_str, domain)
                    if cleaned:
                        subs.add(cleaned)
        except Exception:
            pass
    return subs

PASSIVE_HANDLERS = {
    "shodan": fetch_shodan,
    "shodan-deep": fetch_shodan,
    "virustotal": fetch_virustotal,
    "vt_passive": fetch_virustotal,
    "github_search": fetch_github,
    "gitlab-search": fetch_github,
    "zoomeye": fetch_zoomeye,
    "securitytrails": fetch_securitytrails,
    "chaos": fetch_chaos,
    "crt.sh": fetch_crtsh,
    "crtsh_extended": fetch_crtsh,
    "otx": fetch_alienvault,
    "hackertarget": fetch_hackertarget,
    "anubis": fetch_anubis,
    "threatminer": fetch_threatminer,
    "wayback": fetch_wayback,
    "wayback-html": fetch_wayback,
    "certspotter": fetch_certspotter,
    "rapiddns": fetch_rapiddns,
    "urlscan": fetch_urlscan,
    "jldc": fetch_jldc,
    "subdomaincenter": fetch_subdomaincenter,
    "sub-center-deep": fetch_subdomaincenter,
    "robtex": fetch_robtex,
    "leakix": fetch_leakix,
    "fofa": fetch_fofa,
    "certstream-live": fetch_crtsh,
    "digitorus": fetch_certspotter,
    "mnemonic-pdns": fetch_robtex,
}


async def run_passive_harvester(
    domain: str,
    enabled_sources: Set[str],
    on_yield: Callable[[str, int, Set[str]], Awaitable[None]],
    log: Callable[[str, str], Awaitable[None]]
) -> Set[str]:
    keys = load_api_keys()
    total_discovered = set()
    headers = {"User-Agent": USER_AGENT}

    async with httpx.AsyncClient(headers=headers, follow_redirects=True, verify=False) as client:
        tasks = []
        for src_name, fetcher in PASSIVE_HANDLERS.items():
            if enabled_sources is None or src_name in enabled_sources:
                async def _task(name=src_name, fn=fetcher):
                    await log(f"[{name}] Sorğulanır ({domain})...", "info")
                    try:
                        results = await fn(client, domain, keys, log)
                        count = len(results)
                        if count > 0:
                            await log(f"[{name}] Uğurlu: +{count} subdomain tapıldı", "success")
                            await on_yield(name, count, results)
                        return results
                    except Exception as e:
                        await log(f"[{name}] Xəta: {str(e)}", "dim")
                        return set()

                tasks.append(_task())

        if tasks:
            results_list = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results_list:
                if isinstance(res, set):
                    total_discovered.update(res)

    return total_discovered
