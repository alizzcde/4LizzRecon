"""
External CLI Recon Tools Bridge
Detects and interfaces with installed external binaries (subfinder, findomain, amass, etc.)
Supports both system PATH and local project ./tools/ directory binaries.
"""

import os
import shutil
import asyncio
import re
from typing import Dict, List, Set, Callable, Awaitable

TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "tools")

def get_tool_executable(tool_id: str) -> str:
    """Finds binary in local tools/ directory or system PATH"""
    local_path = os.path.join(TOOLS_DIR, f"{tool_id}.exe")
    if os.path.exists(local_path):
        return local_path
    
    local_path_no_ext = os.path.join(TOOLS_DIR, tool_id)
    if os.path.exists(local_path_no_ext):
        return local_path_no_ext

    return shutil.which(tool_id) or ""

def get_installed_tools_status() -> Dict[str, bool]:
    """
    Checks system PATH and ./tools/ folder for available security tools.
    """
    status = {}
    for tool_id in ["subfinder", "findomain", "amass", "assetfinder", "sublist3r", "subdog", "github-subdomains", "httpx"]:
        exec_path = get_tool_executable(tool_id)
        status[tool_id] = bool(exec_path)
    return status

async def run_external_tool(
    tool_id: str,
    domain: str,
    on_yield: Callable[[str, int, Set[str]], Awaitable[None]],
    log: Callable[[str, str], Awaitable[None]]
) -> Set[str]:
    """
    Runs an external tool asynchronously and streams found subdomains.
    """
    exec_path = get_tool_executable(tool_id)
    if not exec_path:
        return set()

    if tool_id == "subfinder":
        cmd = [exec_path, "-d", domain, "-silent", "-all"]
    elif tool_id == "findomain":
        cmd = [exec_path, "-t", domain, "-q"]
    elif tool_id == "assetfinder":
        cmd = [exec_path, "--subs-only", domain]
    elif tool_id == "amass":
        cmd = [exec_path, "enum", "-passive", "-d", domain]
    else:
        cmd = [exec_path, "-d", domain]

    await log(f"[{tool_id}] Xarici alət işə salınır: {os.path.basename(exec_path)}", "info")

    discovered = set()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            raw = line.decode('utf-8', errors='ignore').strip()
            # Clean domain
            cleaned = re.sub(r'^\*\.', '', raw).strip().lower()
            if (cleaned.endswith('.' + domain) or cleaned == domain) and cleaned not in discovered:
                # Valid RFC check
                if re.match(r'^[a-z0-9]([a-z0-9\-_]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]{0,61}[a-z0-9])?)*$', cleaned):
                    discovered.add(cleaned)

        await proc.wait()
        count = len(discovered)
        if count > 0:
            await log(f"[{tool_id}] Tamamlandı: +{count} unikal subdomain əlavə edildi", "success")
            await on_yield(tool_id, count, discovered)
        else:
            await log(f"[{tool_id}] 0 subdomain qaytardı", "dim")

    except Exception as e:
        await log(f"[{tool_id}] İcra xətası: {str(e)}", "dim")

    return discovered
