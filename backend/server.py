"""
FastAPI Server & WebSocket Orchestrator for Real Recon Suite
"""

import sys
import os
import asyncio
import json
from datetime import datetime
from typing import Dict, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Ensure backend directory is in python path
sys.path.insert(0, os.path.dirname(__file__))

from modules.passive_collector import run_passive_harvester
from modules.dns_resolver import AsyncDNSResolver
from modules.http_prober import run_http_prober
from modules.cli_runner import get_installed_tools_status, run_external_tool
from modules.active_techniques import run_pre_resolve_techniques, run_post_resolve_techniques

app = FastAPI(title="Bug Bounty Recon Suite API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "recon-engine"}

@app.get("/api/tools")
async def get_tools():
    """Returns availability of CLI tools on the host system"""
    return get_installed_tools_status()

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")
EXAMPLE_CONFIG = os.path.join(os.path.dirname(__file__), "config.example.json")

@app.get("/api/config")
async def get_config():
    """Returns current API keys configuration status (masked)"""
    keys = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                keys = json.load(f)
        except Exception:
            pass
    elif os.path.exists(EXAMPLE_CONFIG):
        try:
            with open(EXAMPLE_CONFIG, "r", encoding="utf-8") as f:
                keys = json.load(f)
        except Exception:
            pass
    
    # Return masked or status summary
    status_summary = {k: bool(v.strip()) for k, v in keys.items()}
    return {
        "keys": {k: (v[:4] + "****" + v[-4:]) if len(v) > 8 else ("****" if v else "") for k, v in keys.items()},
        "active_status": status_summary
    }

@app.post("/api/config")
async def save_config(new_config: dict):
    """Saves API keys to config.json"""
    existing = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            pass
    
    # Update non-masked fields
    for k, v in new_config.items():
        if v and not "****" in v:
            existing[k] = v.strip()
        elif v == "":
            existing[k] = ""

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)

    return {"status": "saved", "updated": list(existing.keys())}

class ReconSession:
    def __init__(self, websocket: WebSocket):
        self.ws = websocket
        self.is_running = False
        self.should_stop = False

    async def send(self, data: dict):
        try:
            await self.ws.send_text(json.dumps(data))
        except Exception:
            pass

    async def log(self, message: str, level: str = "info"):
        now_str = datetime.now().strftime("%H:%M:%S")
        await self.send({
            "type": "log",
            "timestamp": now_str,
            "message": message,
            "level": level
        })

    async def update_stats(self, phase: str, found: int, checked: int, live: int, filtered: int):
        await self.send({
            "type": "stats",
            "phase": phase,
            "found": found,
            "checked": checked,
            "live": live,
            "filtered": filtered
        })

    async def run(self, target: str, sources_config: list, tools_config: list, active_techs_config: list, options: dict):
        self.is_running = True
        self.should_stop = False
        target = target.strip().lower()

        # Clean domain
        target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        await self.log(f"4Lizz Recon mühərriki başladıldı: [{target}]", "success")
        await self.update_stats("BAŞLADILIR", 0, 0, 0, 0)

        # 1. Inspect installed tools vs enabled tools
        installed_tools = get_installed_tools_status()
        enabled_tools_set = set(tools_config) if tools_config is not None else None
        if enabled_tools_set is not None:
            active_tools_to_run = [k for k, v in installed_tools.items() if v and k in enabled_tools_set]
        else:
            active_tools_to_run = [k for k, v in installed_tools.items() if v]

        if active_tools_to_run:
            await self.log(f"İstifadə olunacaq CLI alətləri: {', '.join(active_tools_to_run)}", "info")
        else:
            await self.log("Seçilmiş/mövcud CLI aləti yoxdur, yerli asinxron OSINT və DNS mühərriki istifadə olunur", "info")

        # 2. Phase 1: Passive & Pre-Resolve Active Enumeration
        await self.update_stats("RECON MƏRHƏLƏSİ", 0, 0, 0, 0)
        await self.log("1-ci Mərhələ: Passiv OSINT və İlkin Aktiv Texnikalar başladılır...", "info")

        discovered_subs: Set[str] = set()

        async def on_source_yield(source_name: str, count: int, new_subs: Set[str]):
            discovered_subs.update(new_subs)
            await self.send({
                "type": "source_yield",
                "source": source_name,
                "count": count
            })
            await self.update_stats("RECON MƏRHƏLƏSİ", len(discovered_subs), 0, 0, 0)

        # Extract enabled sources from request
        enabled_sources = set(sources_config) if sources_config else set()
        enabled_techs = set(active_techs_config) if active_techs_config else set()

        # Run native API harvesters, external CLI tools, and pre-resolve active techniques concurrently
        all_harvest_tasks = [
            run_passive_harvester(target, enabled_sources, on_source_yield, self.log)
        ]

        for tool_name in active_tools_to_run:
            all_harvest_tasks.append(
                run_external_tool(tool_name, target, on_source_yield, self.log)
            )

        if enabled_techs:
            all_harvest_tasks.append(
                run_pre_resolve_techniques(target, enabled_techs, discovered_subs, on_source_yield, self.log)
            )

        await asyncio.gather(*all_harvest_tasks, return_exceptions=True)

        if self.should_stop:
            await self.log("Skanlama istifadəçi tərəfindən dayandırıldı", "wildcard")
            await self.update_stats("DAYANDIRILDI", len(discovered_subs), 0, 0, 0)
            return

        total_found = len(discovered_subs)
        await self.log(f"İlkin kəşfiyyat tamamlandı: {total_found} ədəd unikal subdomain aşkar edildi", "success")

        if total_found == 0:
            await self.log("Heç bir subdomain tapılmadı. Zəhmət olmasa hədəf domeni yoxlayın.", "dim")
            await self.update_stats("TAMAMLANDI", 0, 0, 0, 0)
            await self.send({"type": "done"})
            return

        # 3. Phase 2: Wildcard Detection
        await self.update_stats("WILDCARD YOXLANIŞI", total_found, 0, 0, 0)
        await self.log("2-ci Mərhələ: Wildcard DNS yoxlanışları aparılır...", "info")

        resolver = AsyncDNSResolver()
        wildcard_ips = await resolver.detect_wildcard(target, self.log)

        if self.should_stop:
            await self.log("Skanlama dayandırıldı", "wildcard")
            await self.update_stats("DAYANDIRILDI", total_found, 0, 0, 0)
            return

        # 4. Phase 3: DNS Resolution
        await self.update_stats("DNS HƏLLİ", total_found, 0, 0, len(wildcard_ips))
        await self.log(f"3-cü Mərhələ: {total_found} subdomain üçün asinxron DNS həlli başladıldı...", "info")

        subs_list = list(discovered_subs)
        resolved_hosts = await resolver.resolve_batch(
            subs_list,
            concurrency=50,
            filter_wildcards=not options.get("maxScope", False)
        )

        resolved_count = len(resolved_hosts)
        filtered_count = total_found - resolved_count
        await self.log(f"DNS həlli tamamlandı: {resolved_count} host aktiv IP ilə uyğunlaşdı ({filtered_count} həll olunmadı və ya wildcard)", "success")
        await self.update_stats("DNS HƏLL OLUNDU", total_found, total_found, 0, filtered_count)

        if self.should_stop:
            await self.log("Skanlama dayandırıldı", "wildcard")
            return

        # 5. Phase 4: Post-Resolve Active Techniques (TLS SAN, PTR, JS Spider, Headers, etc.)
        post_resolve_techs = enabled_techs.intersection({
            "tls-san", "ptr-sweep", "js-spider", "header-miner",
            "vhost-discovery", "favicon-hash", "asn-reverse", "recursive-crawl"
        })

        if post_resolve_techs and resolved_hosts:
            await self.log("4-cü Mərhələ: Aktiv dərin kəşfiyyat (TLS SAN, PTR, JS Spider, Vhost) başladılır...", "info")
            new_post_subs = await run_post_resolve_techniques(
                target, post_resolve_techs, resolved_hosts, on_source_yield, self.log
            )
            
            # If new subdomains were found, resolve them as well
            unresolved_new = [s for s in new_post_subs if s not in {h['subdomain'] for h in resolved_hosts}]
            if unresolved_new:
                await self.log(f"Dərin analizdən aşkar edilən {len(unresolved_new)} yeni subdomain DNS ilə həll edilir...", "info")
                new_resolved = await resolver.resolve_batch(
                    unresolved_new,
                    concurrency=30,
                    filter_wildcards=not options.get("maxScope", False)
                )
                resolved_hosts.extend(new_resolved)
                resolved_count = len(resolved_hosts)
                total_found = len(discovered_subs)

        if self.should_stop:
            await self.log("Skanlama dayandırıldı", "wildcard")
            return

        # 6. Phase 5: HTTP Probing
        do_http = options.get("httpProbing", True)
        live_count = 0

        if do_http and resolved_hosts:
            await self.update_stats("HTTP YOXLAMASI", total_found, 0, 0, filtered_count)
            await self.log(f"5-ci Mərhələ: {resolved_count} aktiv host üçün HTTP status kodu və başlıq skanlaması başladıldı...", "info")

            checked_counter = 0

            async def on_live_found(host_result: dict):
                nonlocal live_count, checked_counter
                live_count += 1
                checked_counter += 1
                await self.send({
                    "type": "subdomain_found",
                    "data": host_result
                })
                await self.update_stats("HTTP YOXLAMASI", total_found, checked_counter, live_count, filtered_count)

            await run_http_prober(
                resolved_hosts,
                concurrency=30,
                on_live_found=on_live_found
            )
        else:
            # Emit raw resolved hosts if HTTP probing is disabled
            for h in resolved_hosts:
                live_count += 1
                await self.send({
                    "type": "subdomain_found",
                    "data": {
                        "subdomain": h["subdomain"],
                        "status": 0,
                        "title": "",
                        "server": "",
                        "category": "DNS",
                        "risk": "INFO",
                        "ip": h.get("ip", ""),
                        "finalUrl": f"http://{h['subdomain']}"
                    }
                })

        # Finished
        await self.update_stats("TAMAMLANDI", total_found, total_found, live_count, filtered_count)
        await self.log(f"Skanlama uğurla yekunlaşdı! Cəmi tapılan: {total_found}, Canlı cavab verən: {live_count}", "success")
        await self.send({"type": "done"})
        self.is_running = False

@app.websocket("/ws/recon")
async def websocket_recon_endpoint(websocket: WebSocket):
    await websocket.accept()
    session = ReconSession(websocket)

    try:
        while True:
            raw_msg = await websocket.receive_text()
            data = json.loads(raw_msg)
            action = data.get("action")

            if action == "start":
                target = data.get("target", "example.com")
                sources = data.get("sources", [])
                tools = data.get("tools", [])
                active_techs = data.get("activeTechniques", [])
                options = data.get("options", {})
                asyncio.create_task(session.run(target, sources, tools, active_techs, options))

            elif action == "stop":
                session.should_stop = True
                await session.log("Dayanma siqnalı alındı...", "wildcard")

    except WebSocketDisconnect:
        session.should_stop = True
    except Exception as e:
        session.should_stop = True

