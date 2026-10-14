"""
Real Async DNS Resolver & Wildcard Detector
Uses dnspython async resolver with public DNS servers.
"""

import asyncio
import uuid
from typing import Dict, List, Set, Tuple, Optional, Callable, Awaitable
import dns.asyncresolver
import dns.resolver

DEFAULT_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"]

class AsyncDNSResolver:
    def __init__(self, nameservers: List[str] = None):
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = nameservers or DEFAULT_NAMESERVERS
        self.resolver.timeout = 2.5
        self.resolver.lifetime = 4.0
        self.wildcard_ips: Set[str] = set()

    async def detect_wildcard(self, domain: str, log: Callable[[str, str], Awaitable[None]]) -> Set[str]:
        """
        Sends queries for non-existent random subdomains to detect wildcard DNS.
        """
        self.wildcard_ips.clear()
        probes = [
            f"probe-wc-{uuid.uuid4().hex[:8]}.{domain}",
            f"rand-chk-{uuid.uuid4().hex[:8]}.{domain}"
        ]

        for probe in probes:
            try:
                answers = await self.resolver.resolve(probe, "A")
                for rdata in answers:
                    ip = rdata.to_text()
                    self.wildcard_ips.add(ip)
                    await log(f"Wildcard DNS aşkar edildi: *.{domain} -> {ip}", "wildcard")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

        if not self.wildcard_ips:
            await log(f"Wildcard DNS yoxlanışı tamamlandı: Wildcard aşkar edilmədi", "info")
        else:
            await log(f"Cəmi {len(self.wildcard_ips)} ədəd wildcard IP aşkar edildi, filtrləmə aktivdir", "info")

        return self.wildcard_ips

    async def resolve_host(self, host: str, sem: asyncio.Semaphore) -> Optional[Dict]:
        """
        Resolve a single host to A record and CNAME
        """
        async with sem:
            try:
                answers = await self.resolver.resolve(host, "A")
                ips = [rdata.to_text() for rdata in answers]
                primary_ip = ips[0] if ips else None

                is_wildcard = primary_ip in self.wildcard_ips if primary_ip else False

                return {
                    "subdomain": host,
                    "ip": primary_ip,
                    "all_ips": ips,
                    "is_wildcard": is_wildcard,
                    "resolved": True
                }
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return {
                    "subdomain": host,
                    "ip": None,
                    "all_ips": [],
                    "is_wildcard": False,
                    "resolved": False
                }
            except Exception:
                return None

    async def resolve_batch(
        self,
        subdomains: List[str],
        concurrency: int = 50,
        filter_wildcards: bool = True
    ) -> List[Dict]:
        """
        Resolves a list of subdomains concurrently.
        """
        sem = asyncio.Semaphore(concurrency)
        tasks = [self.resolve_host(s, sem) for s in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid = []
        for r in results:
            if isinstance(r, dict) and r.get("resolved"):
                if filter_wildcards and r.get("is_wildcard"):
                    continue
                valid.append(r)
        return valid
