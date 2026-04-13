"""
core/recon/param_discovery.py — Hidden Parameter Discovery
===========================================================
Tìm hidden GET/POST parameters bằng:
  - arjun — parameter fuzzing
  - gf patterns — pattern matching cho URLs
"""

import asyncio
import json
import os
import re
import shutil
import tempfile
from typing import List, Dict

from rich.console import Console

console = Console()


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


async def _run_cmd(cmd: str, timeout: int = 300) -> tuple[str, str]:
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="ignore"), stderr.decode(errors="ignore")
    except asyncio.TimeoutError:
        proc.kill()
        return "", f"Timeout after {timeout}s"


# =============================================================================
# arjun — Parameter Discovery
# =============================================================================

async def run_arjun(
    url: str,
    methods: str = "GET,POST",
    passive: bool = False,
    wordlist: str = None,
    rate_limit: int = 10,
) -> List[str]:
    """
    Chạy arjun để tìm hidden parameters.
    Install: pip install arjun
    """
    if not _tool_available("arjun"):
        console.print("[yellow][!] arjun not installed — skipping[/yellow]")
        return []
    
    cmd_parts = [
        f"arjun -u \"{url}\"",
        f"-m {methods}",
        f"--rate-limit {rate_limit}",
        "-t 10",
        "-oJ /dev/stdout",
    ]
    
    if passive:
        cmd_parts.append("--passive")
    
    if wordlist and os.path.exists(wordlist):
        cmd_parts.append(f"-w {wordlist}")
    
    cmd = " ".join(cmd_parts)
    
    try:
        stdout, stderr = await _run_cmd(cmd, timeout=120)
        
        # arjun output là JSON
        params = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                found_params = data.get("parameters", [])
                params.extend(found_params)
            except json.JSONDecodeError:
                continue
        
        console.print(f"[green][✓] arjun: {len(params)} parameters found for {url}[/green]")
        return params
        
    except Exception as e:
        console.print(f"[!] arjun error: {e}")
        return []


async def run_arjun_bulk(
    urls: List[str],
    methods: str = "GET,POST",
    passive: bool = True,
    max_urls: int = 50,
) -> Dict[str, List[str]]:
    """Chạy arjun trên nhiều URLs (giới hạn để tránh quá lâu)."""
    results = {}
    
    for url in urls[:max_urls]:
        params = await run_arjun(url, methods=methods, passive=passive)
        if params:
            results[url] = params
    
    return results


# =============================================================================
# gf patterns — Pattern-based URL filtering
# =============================================================================

GF_PATTERNS = {
    "xss": r"(\?|&)(q|s|search|query|keyword|lang|url|view|cat|name|p|callback|jsonp|api_key|api|redirect|return|r|u|next|data|reference|site|html|val|validate|domain|page|feed|host|port|to|out|navigation|open|file|document|folder|pg|php_path|style|template|php_url|window|action|board|detail|date|download|path|report|src|title)=",
    "sqli": r"(\?|&)(id|select|report|role|update|query|user|name|sort|where|search|params|process|row|view|table|from|sel|results|sleep|fetch|order|keyword|column|field|delete|string|number|filter)=",
    "lfi": r"(\?|&)(file|document|folder|root|path|pg|style|pdf|template|php_path|doc|page|name|cat|dir|action|board|date|detail|download|prefix|include|inc|locate|show|site|type|view|content|layout|mod|conf)=",
    "ssrf": r"(\?|&)(dest|redirect|uri|path|continue|url|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|show|navigation|open)=",
    "redirect": r"(\?|&)(redirect|redir|url|redirect_uri|redirect_url|return|returnTo|return_path|return_to|return_url|rurl|target|to|uri|destination|next|out|view|goto|go|forward|forward_url|jump|jump_url|location)=",
    "idor": r"(\?|&)(id|user|account|number|order|no|doc|key|email|group|profile|edit|report)=",
}


def apply_gf_pattern(urls: List[str], pattern_name: str) -> List[str]:
    """
    Áp dụng gf pattern để lọc URLs.
    pattern_name: xss, sqli, lfi, ssrf, redirect, idor
    """
    if pattern_name not in GF_PATTERNS:
        console.print(f"[!] Unknown gf pattern: {pattern_name}")
        return []
    
    regex = re.compile(GF_PATTERNS[pattern_name], re.IGNORECASE)
    matched = [url for url in urls if regex.search(url)]
    
    console.print(f"[green][✓] gf {pattern_name}: {len(matched)} URLs matched[/green]")
    return matched


def apply_all_gf_patterns(urls: List[str]) -> Dict[str, List[str]]:
    """Áp dụng tất cả gf patterns, trả về dict phân loại."""
    results = {}
    for pattern_name in GF_PATTERNS.keys():
        results[pattern_name] = apply_gf_pattern(urls, pattern_name)
    return results


# =============================================================================
# Parameter Extraction từ URLs
# =============================================================================

def extract_params_from_urls(urls: List[str]) -> List[str]:
    """Extract tất cả parameter names từ URLs."""
    params = set()
    
    for url in urls:
        # Tìm tất cả ?param=value hoặc &param=value
        matches = re.findall(r'[?&]([^=&]+)=', url)
        params.update(matches)
    
    return list(params)


# =============================================================================
# Orchestrator
# =============================================================================

async def run_param_discovery_pipeline(
    urls: List[str],
    run_arjun: bool = False,
    max_arjun_urls: int = 20,
) -> dict:
    """
    Chạy parameter discovery pipeline.
    
    Returns:
        {
            "gf_patterns": {...},
            "extracted_params": [...],
            "arjun_results": {...}
        }
    """
    console.print(f"[cyan][→] Starting parameter discovery on {len(urls)} URLs...[/cyan]")
    
    # 1. Apply gf patterns
    gf_results = apply_all_gf_patterns(urls)
    
    # 2. Extract params từ URLs
    extracted_params = extract_params_from_urls(urls)
    
    # 3. Arjun (optional, vì chậm)
    arjun_results = {}
    if run_arjun:
        console.print(f"[→] Running arjun on {min(max_arjun_urls, len(urls))} URLs...")
        arjun_results = await run_arjun_bulk(urls, max_urls=max_arjun_urls)
    
    console.print(f"\n[bold green][★] Parameter Discovery Summary:[/bold green]")
    console.print(f"  Extracted params: {len(extracted_params)}")
    console.print(f"  XSS candidates: {len(gf_results.get('xss', []))}")
    console.print(f"  SQLi candidates: {len(gf_results.get('sqli', []))}")
    console.print(f"  LFI candidates: {len(gf_results.get('lfi', []))}")
    console.print(f"  SSRF candidates: {len(gf_results.get('ssrf', []))}")
    console.print(f"  Redirect candidates: {len(gf_results.get('redirect', []))}")
    console.print(f"  IDOR candidates: {len(gf_results.get('idor', []))}")
    
    if arjun_results:
        console.print(f"  Arjun discovered: {sum(len(v) for v in arjun_results.values())} params")
    
    return {
        "gf_patterns": gf_results,
        "extracted_params": extracted_params,
        "arjun_results": arjun_results,
    }
