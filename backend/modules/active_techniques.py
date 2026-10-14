"""
Active Reconnaissance Techniques Module
Implements DNS brute force, zone transfer, TLS SAN extraction,
PTR sweep, SPF/DMARC, SRV/DKIM enumeration, DNSSEC walking,
sitemap crawling, JS spidering, header mining, vhost discovery,
favicon hashing, ASN reverse, recursive brute and crawl.
"""

import re
import ssl
import socket
import asyncio
import hashlib
from typing import Set, Dict, List, Callable, Awaitable

import dns.asyncresolver
import dns.resolver
import dns.reversename
import httpx

# Optional imports for advanced features
try:
    import dns.query
    import dns.zone
    _HAS_ZONE_XFR = True
except ImportError:
    _HAS_ZONE_XFR = False

try:
    # pyrefly: ignore [missing-import]
    from cryptography import x509
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# ═══════════════════════════════════════════
#  WORDLISTS
# ═══════════════════════════════════════════

BRUTE_PREFIXES = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "ns3", "ns4",
    "blog", "dev", "staging", "api", "admin", "portal", "vpn", "test", "m",
    "mobile", "app", "shop", "store", "cdn", "images", "img", "static",
    "assets", "media", "video", "docs", "wiki", "support", "help", "status",
    "monitor", "git", "svn", "ci", "jenkins", "jira", "confluence", "grafana",
    "kibana", "elastic", "redis", "mongo", "mysql", "postgres", "db",
    "database", "backup", "bak", "old", "new", "beta", "alpha", "demo",
    "sandbox", "qa", "uat", "prod", "production", "internal", "intranet",
    "extranet", "remote", "proxy", "gateway", "router", "dns", "dhcp",
    "ldap", "ad", "exchange", "outlook", "owa", "autodiscover", "sip",
    "meet", "teams", "chat", "sso", "login", "auth", "oauth", "cloud",
    "aws", "azure", "gcp", "k8s", "kubernetes", "docker", "registry",
    "nexus", "vault", "consul", "prometheus", "www2", "www3", "web",
    "web1", "web2", "app1", "app2", "server", "server1", "server2",
    "host", "node", "worker", "master", "lb", "haproxy", "nginx",
    "crm", "erp", "hr", "finance", "billing", "payment", "analytics",
    "metrics", "log", "logs", "file", "files", "share", "nas",
    "dev1", "dev2", "staging1", "staging2", "test1", "test2",
    "preprod", "stage", "stg", "mx", "mx1", "mx2", "relay",
    "smtp1", "smtp2", "imap", "pop3", "ns", "dns1", "dns2",
    "vpn1", "vpn2", "secure", "api1", "api2", "api-gateway",
    "graphql", "rest", "ws", "wss", "cdn1", "cdn2", "edge", "origin",
    "s3", "storage", "cache", "queue", "mq", "rabbitmq", "kafka",
    "search", "solr", "elasticsearch", "report", "reports", "dashboard",
    "cpanel", "whm", "plesk", "phpmyadmin", "pgadmin",
]

SRV_SERVICES = [
    "_sip._tcp", "_sip._udp", "_sips._tcp",
    "_xmpp-client._tcp", "_xmpp-server._tcp", "_jabber._tcp",
    "_http._tcp", "_https._tcp", "_ldap._tcp", "_ldaps._tcp",
    "_kerberos._tcp", "_kerberos._udp", "_kpasswd._tcp",
    "_gc._tcp", "_imap._tcp", "_imaps._tcp", "_submission._tcp",
    "_caldav._tcp", "_carddav._tcp", "_autodiscover._tcp",
    "_matrix._tcp", "_minecraft._tcp", "_ts3._udp",
]

DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3",
    "mail", "dkim", "s1", "s2", "smtp", "mandrill", "mailgun",
    "amazonses", "cm", "protonmail", "mimecast", "key1", "key2",
    "zendesk1", "zendesk2", "dkim1024", "dkim2048",
]

VHOST_PREFIXES = [
    "dev", "staging", "admin", "api", "internal", "test", "beta",
    "portal", "vpn", "mail", "webmail", "dashboard", "monitor",
    "git", "jenkins", "jira", "wiki", "docs", "status",
]


def _clean(sub: str, domain: str) -> str:
    """Validate and clean a subdomain string"""
    if not sub:
        return ""
    sub = sub.strip().lower()
    sub = re.sub(r'^\*\.', '', sub)
    sub = re.sub(r'^https?://', '', sub)
    sub = sub.split('/')[0].split(':')[0]
    if sub.endswith('.' + domain) or sub == domain:
        if re.match(r'^[a-z0-9]([a-z0-9\-_]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]{0,61}[a-z0-9])?)*$', sub):
            return sub
    return ""


# ═══════════════════════════════════════════
#  PRE-RESOLVE TECHNIQUES (need domain only)
# ═══════════════════════════════════════════

async def run_dns_bruteforce(domain, on_yield, log, existing=None, concurrency=50):
    """Brute force common subdomain prefixes via DNS A-record resolution"""
    await log("[dns-bruteforce] Ümumi prefiks lüğəti ilə DNS brute force başladıldı...", "info")
    discovered = set()
    existing = existing or set()
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    resolver.timeout = 2.5
    resolver.lifetime = 4.0
    sem = asyncio.Semaphore(concurrency)

    async def probe(prefix):
        candidate = f"{prefix}.{domain}"
        if candidate in existing:
            return
        async with sem:
            try:
                await resolver.resolve(candidate, "A")
                c = _clean(candidate, domain)
                if c:
                    discovered.add(c)
            except Exception:
                pass

    await asyncio.gather(*[probe(p) for p in BRUTE_PREFIXES], return_exceptions=True)

    count = len(discovered)
    if count > 0:
        await log(f"[dns-bruteforce] Tamamlandı: +{count} yeni subdomain tapıldı", "success")
        await on_yield("dns-bruteforce", count, discovered)
    else:
        await log("[dns-bruteforce] Heç bir yeni subdomain tapılmadı", "dim")
    return discovered


async def run_zone_transfer(domain, on_yield, log):
    """Attempt AXFR zone transfer against domain nameservers"""
    await log("[zone-transfer] AXFR zone transfer cəhdi başladıldı...", "info")
    discovered = set()

    if not _HAS_ZONE_XFR:
        await log("[zone-transfer] dns.query/dns.zone modulları mövcud deyil, atlanır", "dim")
        return discovered

    resolver = dns.asyncresolver.Resolver()
    try:
        ns_answers = await resolver.resolve(domain, "NS")
        nameservers = [str(ns).rstrip('.') for ns in ns_answers]
    except Exception:
        await log("[zone-transfer] NS qeydləri tapılmadı", "dim")
        return discovered

    for ns in nameservers[:3]:
        try:
            ns_ips = await resolver.resolve(ns, "A")
            ns_ip = str(list(ns_ips)[0])

            loop = asyncio.get_event_loop()
            def do_axfr(ip=ns_ip, dom=domain):
                try:
                    return dns.zone.from_xfr(dns.query.xfr(ip, dom, timeout=10))
                except Exception:
                    return None

            zone = await loop.run_in_executor(None, do_axfr)

            if zone:
                for name in zone.nodes:
                    full = f"{name}.{domain}" if str(name) != "@" else domain
                    c = _clean(full, domain)
                    if c:
                        discovered.add(c)
                await log(f"[zone-transfer] AXFR uğurlu: {ns} → +{len(discovered)} qeyd", "success")
                break
            else:
                await log(f"[zone-transfer] {ns}: AXFR rədd edildi", "dim")
        except Exception:
            await log(f"[zone-transfer] {ns}: bağlantı xətası", "dim")

    if discovered:
        await on_yield("zone-transfer", len(discovered), discovered)
    else:
        await log("[zone-transfer] Heç bir NS zone transfer qəbul etmədi", "dim")
    return discovered


async def run_spf_dmarc(domain, on_yield, log):
    """Extract subdomains from SPF includes, DMARC, and MX records"""
    await log("[spf-dmarc] SPF/DMARC/MX qeydləri yoxlanılır...", "info")
    discovered = set()
    resolver = dns.asyncresolver.Resolver()

    # SPF
    try:
        txt_answers = await resolver.resolve(domain, "TXT")
        for rdata in txt_answers:
            txt = str(rdata).strip('"')
            if 'spf' in txt.lower():
                for d in re.findall(r'include:([^\s]+)', txt) + re.findall(r'redirect=([^\s]+)', txt):
                    c = _clean(d, domain)
                    if c:
                        discovered.add(c)
    except Exception:
        pass

    # DMARC
    try:
        answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            for d in re.findall(rf'([a-zA-Z0-9._-]+\.{re.escape(domain)})', str(rdata)):
                c = _clean(d, domain)
                if c:
                    discovered.add(c)
    except Exception:
        pass

    # MX
    try:
        mx_answers = await resolver.resolve(domain, "MX")
        for rdata in mx_answers:
            c = _clean(str(rdata.exchange).rstrip('.'), domain)
            if c:
                discovered.add(c)
    except Exception:
        pass

    count = len(discovered)
    if count > 0:
        await log(f"[spf-dmarc] +{count} subdomain DNS qeydlərindən tapıldı", "success")
        await on_yield("spf-dmarc", count, discovered)
    else:
        await log("[spf-dmarc] DNS qeydlərindən yeni subdomain tapılmadı", "dim")
    return discovered


async def run_srv_enum(domain, on_yield, log, concurrency=20):
    """Enumerate SRV records for common services"""
    await log("[srv-enum] SRV qeydləri yoxlanılır...", "info")
    discovered = set()
    sem = asyncio.Semaphore(concurrency)
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    async def check(svc):
        async with sem:
            try:
                answers = await resolver.resolve(f"{svc}.{domain}", "SRV")
                for rdata in answers:
                    c = _clean(str(rdata.target).rstrip('.'), domain)
                    if c:
                        discovered.add(c)
            except Exception:
                pass

    await asyncio.gather(*[check(s) for s in SRV_SERVICES], return_exceptions=True)

    count = len(discovered)
    if count > 0:
        await log(f"[srv-enum] +{count} subdomain SRV qeydlərindən tapıldı", "success")
        await on_yield("srv-enum", count, discovered)
    else:
        await log("[srv-enum] SRV qeydlərindən subdomain tapılmadı", "dim")
    return discovered


async def run_dkim_enum(domain, on_yield, log, concurrency=10):
    """Enumerate DKIM selectors to find related subdomains"""
    await log("[dkim-enum] DKIM selektorları yoxlanılır...", "info")
    discovered = set()
    found_selectors = []
    sem = asyncio.Semaphore(concurrency)
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    async def check(selector):
        dkim_host = f"{selector}._domainkey.{domain}"
        async with sem:
            try:
                await resolver.resolve(dkim_host, "TXT")
                found_selectors.append(selector)
                c = _clean(dkim_host, domain)
                if c:
                    discovered.add(c)
                # Check CNAME too
                try:
                    cname_answers = await resolver.resolve(dkim_host, "CNAME")
                    for rdata in cname_answers:
                        c2 = _clean(str(rdata.target).rstrip('.'), domain)
                        if c2:
                            discovered.add(c2)
                except Exception:
                    pass
            except Exception:
                pass

    await asyncio.gather(*[check(s) for s in DKIM_SELECTORS], return_exceptions=True)

    count = len(discovered)
    if count > 0:
        await log(f"[dkim-enum] +{count} DKIM qeydi tapıldı (selektorlar: {', '.join(found_selectors)})", "success")
        await on_yield("dkim-enum", count, discovered)
    else:
        await log("[dkim-enum] DKIM-dən subdomain tapılmadı", "dim")
    return discovered


async def run_dnssec_walk(domain, on_yield, log):
    """Attempt NSEC zone walking for DNSSEC-enabled domains"""
    await log("[dnssec-walk] DNSSEC NSEC zone walking cəhdi...", "info")
    discovered = set()
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8

    # Check DNSSEC
    try:
        await resolver.resolve(domain, "DNSKEY")
    except Exception:
        await log("[dnssec-walk] Domain DNSSEC istifadə etmir", "dim")
        return discovered

    # NSEC walking
    current = domain
    for _ in range(200):
        try:
            answers = await resolver.resolve(current, "NSEC")
            found_next = False
            for rdata in answers:
                next_name = str(rdata.next).rstrip('.')
                if next_name.endswith('.' + domain) and next_name != current:
                    c = _clean(next_name, domain)
                    if c and c not in discovered:
                        discovered.add(c)
                        current = c
                        found_next = True
                        break
            if not found_next:
                break
        except Exception:
            break

    count = len(discovered)
    if count > 0:
        await log(f"[dnssec-walk] +{count} subdomain NSEC-dən tapıldı", "success")
        await on_yield("dnssec-walk", count, discovered)
    else:
        await log("[dnssec-walk] NSEC-dən subdomain tapılmadı", "dim")
    return discovered


async def run_sitemap_crawler(domain, on_yield, log):
    """Crawl robots.txt and sitemap.xml for subdomain references"""
    await log("[sitemap-crawler] robots.txt və sitemap.xml yoxlanılır...", "info")
    discovered = set()

    async with httpx.AsyncClient(verify=False, timeout=8, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
        for scheme in ["https", "http"]:
            try:
                r = await client.get(f"{scheme}://{domain}/robots.txt")
                if r.status_code == 200:
                    sitemaps = re.findall(r'Sitemap:\s*(https?://\S+)', r.text, re.IGNORECASE)
                    for url in re.findall(rf'(https?://[a-zA-Z0-9._-]+\.{re.escape(domain)}[^\s]*)', r.text):
                        host = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]
                        c = _clean(host, domain)
                        if c:
                            discovered.add(c)
                    # Fetch sitemaps
                    for sm_url in sitemaps[:5]:
                        try:
                            sr = await client.get(sm_url)
                            if sr.status_code == 200:
                                for loc in re.findall(r'<loc>(.*?)</loc>', sr.text):
                                    host = re.sub(r'^https?://', '', loc).split('/')[0].split(':')[0]
                                    c = _clean(host, domain)
                                    if c:
                                        discovered.add(c)
                        except Exception:
                            pass
                    break
            except Exception:
                pass

        # Direct sitemap.xml
        for scheme in ["https", "http"]:
            try:
                r = await client.get(f"{scheme}://{domain}/sitemap.xml")
                if r.status_code == 200:
                    for loc in re.findall(r'<loc>(.*?)</loc>', r.text):
                        host = re.sub(r'^https?://', '', loc).split('/')[0].split(':')[0]
                        c = _clean(host, domain)
                        if c:
                            discovered.add(c)
                    break
            except Exception:
                pass

    count = len(discovered)
    if count > 0:
        await log(f"[sitemap-crawler] +{count} subdomain sitemap-dan tapıldı", "success")
        await on_yield("sitemap-crawler", count, discovered)
    else:
        await log("[sitemap-crawler] Sitemap-dan subdomain tapılmadı", "dim")
    return discovered


async def run_recursive_brute(domain, existing_subs, on_yield, log, concurrency=30):
    """Recursive brute force on discovered subdomains (e.g., dev.api.domain.com)"""
    await log("[recursive-brute] Rekursiv brute force başladıldı...", "info")
    discovered = set()
    short = ["dev", "staging", "api", "admin", "test", "www", "mail", "internal",
             "vpn", "beta", "portal", "cdn", "app", "prod", "qa"]

    # Pick interesting base subdomains to recurse
    bases = [s for s in existing_subs if s.replace(f".{domain}", "").count('.') == 0][:15]
    if not bases:
        bases = list(existing_subs)[:5]

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = 2.5
    resolver.lifetime = 4.0
    sem = asyncio.Semaphore(concurrency)

    async def probe(candidate):
        if candidate in existing_subs:
            return
        async with sem:
            try:
                await resolver.resolve(candidate, "A")
                c = _clean(candidate, domain)
                if c:
                    discovered.add(c)
            except Exception:
                pass

    tasks = [probe(f"{p}.{base}") for base in bases for p in short]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    count = len(discovered)
    if count > 0:
        await log(f"[recursive-brute] +{count} subdomain rekursiv brute force-dan tapıldı", "success")
        await on_yield("recursive-brute", count, discovered)
    else:
        await log("[recursive-brute] Rekursiv brute force-dan subdomain tapılmadı", "dim")
    return discovered


# ═══════════════════════════════════════════
#  POST-RESOLVE TECHNIQUES (need resolved hosts)
# ═══════════════════════════════════════════

async def run_tls_san(domain, resolved_hosts, on_yield, log, concurrency=30):
    """Extract Subject Alternative Names (SAN) from TLS certificates on port 443"""
    await log("[tls-san] TLS sertifikat SAN çıxarılması başladıldı...", "info")
    discovered = set()

    sem = asyncio.Semaphore(concurrency)
    targets = list({h.get("subdomain", "") for h in resolved_hosts if h.get("subdomain")})[:100]

    async def check(hostname):
        async with sem:
            try:
                loop = asyncio.get_event_loop()
                def _get_cert_info(hn=hostname):
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    # Try getting parsed cert with default context
                    try:
                        ctx_val = ssl.create_default_context()
                        with socket.create_connection((hn, 443), timeout=3) as sock:
                            with ctx_val.wrap_socket(sock, server_hostname=hn) as ssock:
                                return ssock.getpeercert()
                    except Exception:
                        pass
                    # If verification failed (e.g. self signed or expired), fetch binary cert if crypto available
                    if _HAS_CRYPTO:
                        try:
                            with socket.create_connection((hn, 443), timeout=3) as sock:
                                with ctx.wrap_socket(sock, server_hostname=hn) as ssock:
                                    return ssock.getpeercert(binary_form=True)
                        except Exception:
                            pass
                    return None

                cert_data = await loop.run_in_executor(None, _get_cert_info)
                if isinstance(cert_data, dict):
                    # Standard parsed cert dict
                    for item in cert_data.get('subjectAltName', []):
                        if len(item) == 2 and item[0].lower() == 'dns':
                            c = _clean(item[1], domain)
                            if c:
                                discovered.add(c)
                    for sub in cert_data.get('subject', ()):
                        for attr in sub:
                            if len(attr) == 2 and attr[0] == 'commonName':
                                c = _clean(attr[1], domain)
                                if c:
                                    discovered.add(c)
                elif cert_data and _HAS_CRYPTO:
                    cert = x509.load_der_x509_certificate(cert_data)
                    try:
                        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        for dns_name in san_ext.value.get_values_for_type(x509.DNSName):
                            c = _clean(dns_name, domain)
                            if c:
                                discovered.add(c)
                    except Exception:
                        pass
            except Exception:
                pass

    await asyncio.gather(*[check(h) for h in targets], return_exceptions=True)

    count = len(discovered)
    if count > 0:
        await log(f"[tls-san] +{count} subdomain TLS SAN-dan çıxarıldı", "success")
        await on_yield("tls-san", count, discovered)
    else:
        await log("[tls-san] TLS SAN-dan subdomain tapılmadı", "dim")
    return discovered


async def run_ptr_sweep(domain, resolved_hosts, on_yield, log, concurrency=30):
    """Reverse DNS (PTR) lookup on discovered IP addresses"""
    await log("[ptr-sweep] Əks DNS (PTR) axtarışı başladıldı...", "info")
    discovered = set()
    ips = list({h.get("ip", "") for h in resolved_hosts if h.get("ip")})

    sem = asyncio.Semaphore(concurrency)
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    async def reverse(ip):
        async with sem:
            try:
                rev = dns.reversename.from_address(ip)
                answers = await resolver.resolve(rev, "PTR")
                for rdata in answers:
                    c = _clean(str(rdata).rstrip('.'), domain)
                    if c:
                        discovered.add(c)
            except Exception:
                pass

    await asyncio.gather(*[reverse(ip) for ip in ips], return_exceptions=True)

    count = len(discovered)
    if count > 0:
        await log(f"[ptr-sweep] +{count} subdomain PTR-dən tapıldı", "success")
        await on_yield("ptr-sweep", count, discovered)
    else:
        await log("[ptr-sweep] PTR-dən subdomain tapılmadı", "dim")
    return discovered


async def run_js_spider(domain, resolved_hosts, on_yield, log, concurrency=10):
    """Spider JavaScript files for subdomain references"""
    await log("[js-spider] JavaScript fayllarında subdomain axtarışı...", "info")
    discovered = set()
    sem = asyncio.Semaphore(concurrency)
    hosts = [h.get("subdomain", "") for h in resolved_hosts if h.get("subdomain")][:30]
    pattern = re.compile(rf'([a-zA-Z0-9_.-]+\.{re.escape(domain)})')

    async with httpx.AsyncClient(verify=False, timeout=6, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
        async def spider(host):
            async with sem:
                for scheme in ["https", "http"]:
                    try:
                        r = await client.get(f"{scheme}://{host}")
                        if r.status_code != 200:
                            continue
                        # Search HTML for domain refs
                        for m in pattern.findall(r.text):
                            c = _clean(m, domain)
                            if c:
                                discovered.add(c)
                        # Find and fetch JS files
                        for js_path in re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', r.text)[:10]:
                            try:
                                if js_path.startswith('//'):
                                    js_url = f"{scheme}:{js_path}"
                                elif js_path.startswith('/'):
                                    js_url = f"{scheme}://{host}{js_path}"
                                elif not js_path.startswith('http'):
                                    js_url = f"{scheme}://{host}/{js_path}"
                                else:
                                    js_url = js_path
                                jr = await client.get(js_url)
                                if jr.status_code == 200:
                                    for m in pattern.findall(jr.text):
                                        c = _clean(m, domain)
                                        if c:
                                            discovered.add(c)
                            except Exception:
                                pass
                        break
                    except Exception:
                        pass

        await asyncio.gather(*[spider(h) for h in hosts], return_exceptions=True)

    count = len(discovered)
    if count > 0:
        await log(f"[js-spider] +{count} subdomain JS fayllarından tapıldı", "success")
        await on_yield("js-spider", count, discovered)
    else:
        await log("[js-spider] JS-dən subdomain tapılmadı", "dim")
    return discovered


async def run_header_miner(domain, resolved_hosts, on_yield, log, concurrency=15):
    """Extract subdomains from HTTP response headers (CSP, Location, etc.)"""
    await log("[header-miner] HTTP başlıqlarından subdomain axtarışı...", "info")
    discovered = set()
    sem = asyncio.Semaphore(concurrency)
    hosts = [h.get("subdomain", "") for h in resolved_hosts if h.get("subdomain")][:50]
    pattern = re.compile(rf'([a-zA-Z0-9_.-]+\.{re.escape(domain)})')

    async with httpx.AsyncClient(verify=False, timeout=5, follow_redirects=False, headers={"User-Agent": USER_AGENT}) as client:
        async def check(host):
            async with sem:
                for scheme in ["https", "http"]:
                    try:
                        r = await client.get(f"{scheme}://{host}")
                        all_headers = ' '.join(f"{k}: {v}" for k, v in r.headers.items())
                        for m in pattern.findall(all_headers):
                            c = _clean(m, domain)
                            if c:
                                discovered.add(c)
                        break
                    except Exception:
                        pass

        await asyncio.gather(*[check(h) for h in hosts], return_exceptions=True)

    count = len(discovered)
    if count > 0:
        await log(f"[header-miner] +{count} subdomain HTTP başlıqlarından tapıldı", "success")
        await on_yield("header-miner", count, discovered)
    else:
        await log("[header-miner] Başlıqlardan subdomain tapılmadı", "dim")
    return discovered


async def run_vhost_discovery(domain, resolved_hosts, on_yield, log, concurrency=15):
    """Virtual host discovery by probing IPs with different Host headers"""
    await log("[vhost-discovery] Virtual host axtarışı başladıldı...", "info")
    discovered = set()
    sem = asyncio.Semaphore(concurrency)

    # Group by IP
    ip_hosts = {}
    for h in resolved_hosts:
        ip = h.get("ip", "")
        if ip:
            ip_hosts.setdefault(ip, set()).add(h.get("subdomain", ""))

    async with httpx.AsyncClient(verify=False, timeout=4, follow_redirects=False) as client:
        for ip, known in list(ip_hosts.items())[:5]:
            # Baseline
            baseline_sig = None
            ref_host = list(known)[0]
            used_scheme = "https"
            for scheme in ["https", "http"]:
                try:
                    r = await client.get(f"{scheme}://{ip}", headers={"Host": ref_host})
                    baseline_sig = (r.status_code, len(r.text))
                    used_scheme = scheme
                    break
                except Exception:
                    pass

            if not baseline_sig:
                continue

            async def test_vhost(t_ip, prefix, baseline, scheme, known_set):
                vhost = f"{prefix}.{domain}"
                if vhost in known_set:
                    return
                async with sem:
                    try:
                        r = await client.get(f"{scheme}://{t_ip}", headers={"Host": vhost})
                        # Different response may indicate a valid vhost
                        if r.status_code != baseline[0] or abs(len(r.text) - baseline[1]) > 200:
                            c = _clean(vhost, domain)
                            if c:
                                discovered.add(c)
                    except Exception:
                        pass

            await asyncio.gather(
                *[test_vhost(ip, p, baseline_sig, used_scheme, known) for p in VHOST_PREFIXES],
                return_exceptions=True
            )

    count = len(discovered)
    if count > 0:
        await log(f"[vhost-discovery] +{count} virtual host tapıldı", "success")
        await on_yield("vhost-discovery", count, discovered)
    else:
        await log("[vhost-discovery] Yeni virtual host tapılmadı", "dim")
    return discovered


async def run_favicon_hash(domain, resolved_hosts, on_yield, log, concurrency=10):
    """Compute favicon hashes from discovered hosts (informational)"""
    await log("[favicon-hash] Favicon hash hesablanması başladıldı...", "info")
    discovered = set()
    hashes = {}
    sem = asyncio.Semaphore(concurrency)
    hosts = [h.get("subdomain", "") for h in resolved_hosts if h.get("subdomain")][:20]

    async with httpx.AsyncClient(verify=False, timeout=5, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
        async def get_fav(host):
            async with sem:
                for scheme in ["https", "http"]:
                    try:
                        r = await client.get(f"{scheme}://{host}/favicon.ico")
                        if r.status_code == 200 and len(r.content) > 100:
                            h_val = hashlib.md5(r.content).hexdigest()
                            hashes[host] = h_val
                            break
                    except Exception:
                        pass

        await asyncio.gather(*[get_fav(h) for h in hosts], return_exceptions=True)

    unique = set(hashes.values())
    if unique:
        await log(f"[favicon-hash] {len(unique)} unikal favicon hash tapıldı ({len(hashes)} hostdan)", "info")
    else:
        await log("[favicon-hash] Favicon tapılmadı", "dim")

    # Favicon hash is informational; full Shodan correlation needs paid API
    if discovered:
        await on_yield("favicon-hash", len(discovered), discovered)
    return discovered


async def run_asn_reverse(domain, resolved_hosts, on_yield, log):
    """ASN reverse lookup on discovered IPs via Team Cymru DNS"""
    await log("[asn-reverse] ASN əks axtarışı başladıldı...", "info")
    discovered = set()
    ips = list({h.get("ip", "") for h in resolved_hosts if h.get("ip")})[:20]

    if not ips:
        await log("[asn-reverse] IP ünvanı yoxdur", "dim")
        return discovered

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    asns = set()

    for ip in ips:
        try:
            parts = ip.split('.')
            rev = '.'.join(reversed(parts))
            answers = await resolver.resolve(f"{rev}.origin.asn.cymru.com", "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                asn = txt.split('|')[0].strip()
                if asn:
                    asns.add(asn)
        except Exception:
            pass

    if asns:
        await log(f"[asn-reverse] {len(asns)} ASN tapıldı: {', '.join(list(asns)[:5])}", "info")
    else:
        await log("[asn-reverse] ASN məlumatı tapılmadı", "dim")

    if discovered:
        await on_yield("asn-reverse", len(discovered), discovered)
    return discovered


async def run_recursive_crawl(domain, resolved_hosts, on_yield, log, concurrency=10):
    """Crawl discovered pages for links containing subdomains"""
    await log("[recursive-crawl] Səhifə linklərində subdomain axtarışı...", "info")
    discovered = set()
    sem = asyncio.Semaphore(concurrency)
    hosts = [h.get("subdomain", "") for h in resolved_hosts if h.get("subdomain")][:20]
    pattern = re.compile(rf'([a-zA-Z0-9_.-]+\.{re.escape(domain)})')

    async with httpx.AsyncClient(verify=False, timeout=5, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
        async def crawl(host):
            async with sem:
                for scheme in ["https", "http"]:
                    try:
                        r = await client.get(f"{scheme}://{host}")
                        if r.status_code == 200:
                            for m in pattern.findall(r.text):
                                c = _clean(m, domain)
                                if c:
                                    discovered.add(c)
                            # Follow href links
                            for href in re.findall(r'href=["\']([^"\']+)["\']', r.text)[:30]:
                                h_from = re.sub(r'^https?://', '', href).split('/')[0].split(':')[0]
                                c = _clean(h_from, domain)
                                if c:
                                    discovered.add(c)
                            break
                    except Exception:
                        pass

        await asyncio.gather(*[crawl(h) for h in hosts], return_exceptions=True)

    count = len(discovered)
    if count > 0:
        await log(f"[recursive-crawl] +{count} subdomain linklərdən tapıldı", "success")
        await on_yield("recursive-crawl", count, discovered)
    else:
        await log("[recursive-crawl] Linklərdən subdomain tapılmadı", "dim")
    return discovered


# ═══════════════════════════════════════════
#  DISPATCHER FUNCTIONS
# ═══════════════════════════════════════════

async def run_pre_resolve_techniques(domain, enabled, existing_subs, on_yield, log):
    """Run active techniques that don't require resolved host data"""
    all_discovered = set()
    tasks = []

    if "dns-bruteforce" in enabled:
        tasks.append(run_dns_bruteforce(domain, on_yield, log, existing_subs))
    if "zone-transfer" in enabled:
        tasks.append(run_zone_transfer(domain, on_yield, log))
    if "spf-dmarc" in enabled:
        tasks.append(run_spf_dmarc(domain, on_yield, log))
    if "srv-enum" in enabled:
        tasks.append(run_srv_enum(domain, on_yield, log))
    if "dkim-enum" in enabled:
        tasks.append(run_dkim_enum(domain, on_yield, log))
    if "dnssec-walk" in enabled:
        tasks.append(run_dnssec_walk(domain, on_yield, log))
    if "sitemap-crawler" in enabled:
        tasks.append(run_sitemap_crawler(domain, on_yield, log))
    if "recursive-brute" in enabled and existing_subs:
        tasks.append(run_recursive_brute(domain, existing_subs, on_yield, log))
    if "permutation" in enabled and existing_subs:
        async def _run_perm():
            from modules.permutation_engine import run_permutation_resolver
            from modules.dns_resolver import AsyncDNSResolver
            perm_resolver = AsyncDNSResolver()
            results = await run_permutation_resolver(
                list(existing_subs)[:50], domain, perm_resolver, log, on_yield, limit=300
            )
            subs = set()
            if isinstance(results, list):
                for r in results:
                    if isinstance(r, dict) and r.get("subdomain"):
                        subs.add(r["subdomain"])
            return subs
        tasks.append(_run_perm())

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, set):
                all_discovered.update(res)

    return all_discovered


async def run_post_resolve_techniques(domain, enabled, resolved_hosts, on_yield, log):
    """Run active techniques that require resolved host data"""
    all_discovered = set()
    tasks = []

    if "tls-san" in enabled:
        tasks.append(run_tls_san(domain, resolved_hosts, on_yield, log))
    if "ptr-sweep" in enabled:
        tasks.append(run_ptr_sweep(domain, resolved_hosts, on_yield, log))
    if "js-spider" in enabled:
        tasks.append(run_js_spider(domain, resolved_hosts, on_yield, log))
    if "header-miner" in enabled:
        tasks.append(run_header_miner(domain, resolved_hosts, on_yield, log))
    if "vhost-discovery" in enabled:
        tasks.append(run_vhost_discovery(domain, resolved_hosts, on_yield, log))
    if "favicon-hash" in enabled:
        tasks.append(run_favicon_hash(domain, resolved_hosts, on_yield, log))
    if "asn-reverse" in enabled:
        tasks.append(run_asn_reverse(domain, resolved_hosts, on_yield, log))
    if "recursive-crawl" in enabled:
        tasks.append(run_recursive_crawl(domain, resolved_hosts, on_yield, log))

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, set):
                all_discovered.update(res)

    return all_discovered
