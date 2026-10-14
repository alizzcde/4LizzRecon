"""
DNS Permutation & Alteration Engine
Generates smart mutated subdomains (altdns / ripgen style) and resolves them asynchronously.
"""

import re
import asyncio
from typing import Set, List, Dict, Callable, Awaitable

COMMON_ENVIRONMENTS = ["dev", "stage", "staging", "test", "qa", "uat", "prod", "corp", "internal", "local"]
COMMON_SERVICES = ["api", "admin", "portal", "auth", "login", "vpn", "sso", "mail", "gw", "gateway", "app", "web", "cdn", "k8s"]
SEPARATORS = ["-", ""]

def generate_permutations(seed_subdomains: List[str], domain: str, max_candidates: int = 500) -> Set[str]:
    """
    Analyzes known subdomains, extracts prefixes and words, and creates high-probability mutations.
    """
    candidates = set()
    domain_clean = domain.lower().strip()

    # Extract base names from subdomains (e.g. "auth-dev.domain.com" -> ["auth", "dev"])
    extracted_words = set()
    for sub in seed_subdomains[:80]:
        prefix = sub.replace(f".{domain_clean}", "")
        parts = re.split(r'[-_.]', prefix)
        for p in parts:
            if p and len(p) >= 2 and not p.isdigit():
                extracted_words.add(p)

    target_words = list(extracted_words)[:30] or COMMON_SERVICES[:8]

    # Rule 1: Combine known words with environments (e.g. word-dev, word-stage, dev-word)
    for word in target_words:
        for env in COMMON_ENVIRONMENTS[:6]:
            for sep in ["-", ""]:
                candidates.add(f"{word}{sep}{env}.{domain_clean}")
                candidates.add(f"{env}{sep}{word}.{domain_clean}")
                if len(candidates) >= max_candidates:
                    return candidates

    # Rule 2: Number mutations (api -> api1, api2, api-v2, v1, v2)
    for word in target_words[:15]:
        for n in ["1", "2", "3", "01"]:
            candidates.add(f"{word}{n}.{domain_clean}")
            candidates.add(f"{word}-{n}.{domain_clean}")
            candidates.add(f"{word}-v{n}.{domain_clean}")
            if len(candidates) >= max_candidates:
                return candidates

    # Remove already known subdomains from candidates
    existing = set(seed_subdomains)
    return {c for c in candidates if c not in existing}

async def run_permutation_resolver(
    seed_subdomains: List[str],
    domain: str,
    resolver,
    log: Callable[[str, str], Awaitable[None]],
    on_yield: Callable[[str, int, Set[str]], Awaitable[None]],
    limit: int = 400
) -> List[Dict]:
    """
    Generates permutations and performs async DNS resolution to discover hidden staging/QA hosts.
    """
    candidates = list(generate_permutations(seed_subdomains, domain, max_candidates=limit))
    if not candidates:
        return []

    await log(f"[Permutasiya] {len(candidates)} ədəd ağıllı kombinasiya generasiya edildi, DNS yoxlanılır...", "info")

    resolved_permutations = await resolver.resolve_batch(
        candidates,
        concurrency=60,
        filter_wildcards=True
    )

    valid_subs = {r["subdomain"] for r in resolved_permutations}
    count = len(valid_subs)

    if count > 0:
        await log(f"[Permutasiya] Uğurlu: +{count} ədəd gizli subdomain aşkar edildi!", "success")
        await on_yield("permutation", count, valid_subs)
    else:
        await log("[Permutasiya] Əlavə aktiv tapılmadı", "dim")

    return resolved_permutations
