"""
core/recon/passive_sources.py — Passive Subdomain Discovery
============================================================
Thu thập subdomains từ các nguồn công khai:
  - crt.sh (Certificate Transparency)
  - Wayback Machine (web.archive.org)
  - VirusTotal API
  - GitHub (github-subdomains tool)
"""

import asyncio
import json
import re
import subprocess
from typing import List
from urllib.parse import quote

import httpx
from dotenv import load_dotenv
from rich.console import Console

load_dotenv()
console = Console()


# =============================================================================
# crt.sh — Certificate Transparency Logs
# =============================================================================

async def fetch_crtsh(domain: str) -> List[str]:
    """Lấy subdomains từ crt.sh (SSL certificate logs)."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for cert in data:
                    name_value = cert.get("name_value", "")
                    # name_value có thể chứa nhiều domains, ngăn cách bởi \n
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        # Loại bỏ wildcard
                        if "*" not in name and domain in name:
                            subdomains.add(name)
                console.print(f"[✓] crt.sh: {len(subdomains)} subdomains")
            else:
                console.print(f"[!] crt.sh: HTTP {resp.status_code}")
    except Exception as e:
        console.print(f"[!] crt.sh error: {e}")
    
    return list(subdomains)


# =============================================================================
# Wayback Machine — web.archive.org
# =============================================================================

async def fetch_wayback(domain: str) -> List[str]:
    """Lấy subdomains từ Wayback Machine CDX API."""
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    subdomains = set()
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    # Extract domain từ URL
                    match = re.search(r'https?://([^/]+)', line)
                    if match:
                        host = match.group(1).lower()
                        # Loại bỏ www. và port
                        host = re.sub(r'^www\.', '', host)
                        host = re.sub(r':\d+$', '', host)
                        if domain in host:
                            subdomains.add(host)
                console.print(f"[✓] wayback: {len(subdomains)} subdomains")
            else:
                console.print(f"[!] wayback: HTTP {resp.status_code}")
    except Exception as e:
        console.print(f"[!] wayback error: {e}")
    
    return list(subdomains)


# =============================================================================
# VirusTotal API
# =============================================================================

async def fetch_virustotal(domain: str, api_key: str = None) -> List[str]:
    """Lấy subdomains từ VirusTotal API."""
    if not api_key:
        console.print("[!] virustotal: API key not provided, skipping")
        return []
    
    url = f"https://www.virustotal.com/vtapi/v2/domain/report"
    params = {"apikey": api_key, "domain": domain}
    subdomains = set()
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, params=params)
            if resp.status_code == 200:
                data = resp.json()
                # Subdomains từ domain_siblings
                for sub in data.get("subdomains", []):
                    subdomains.add(sub.lower())
                console.print(f"[✓] virustotal: {len(subdomains)} subdomains")
            else:
                console.print(f"[!] virustotal: HTTP {resp.status_code}")
    except Exception as e:
        console.print(f"[!] virustotal error: {e}")
    
    return list(subdomains)


# =============================================================================
# GitHub Subdomains (github-subdomains tool)
# =============================================================================

async def fetch_github_subdomains(domain: str, github_token: str = None) -> List[str]:
    """
    Chạy github-subdomains tool để scrape subdomains từ GitHub repos.
    Cần cài: go install github.com/gwen001/github-subdomains@latest
    """
    if not github_token:
        console.print("[!] github-subdomains: GitHub token not provided, skipping")
        return []
    
    try:
        cmd = f"github-subdomains -d {domain} -t {github_token} -o /dev/stdout"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        
        if proc.returncode != 0:
            if "not found" in stderr.decode():
                console.print("[!] github-subdomains: tool not installed")
            else:
                console.print(f"[!] github-subdomains: {stderr.decode().strip()}")
            return []
        
        subdomains = []
        for line in stdout.decode().splitlines():
            line = line.strip().lower()
            if line and domain in line:
                subdomains.append(line)
        
        console.print(f"[✓] github-subdomains: {len(subdomains)} subdomains")
        return subdomains
        
    except asyncio.TimeoutError:
        console.print("[!] github-subdomains: timeout after 120s")
        return []
    except Exception as e:
        console.print(f"[!] github-subdomains error: {e}")
        return []


# =============================================================================
# Orchestrator — Chạy tất cả passive sources song song
# =============================================================================

async def run_passive_sources(
    domain: str,
    virustotal_key: str = None,
    github_token: str = None
) -> List[str]:
    """
    Chạy tất cả passive sources song song, merge và deduplicate.
    """
    console.print(f"[cyan][→] Running passive subdomain discovery for {domain}...[/cyan]")
    
    tasks = [
        fetch_crtsh(domain),
        fetch_wayback(domain),
        fetch_virustotal(domain, virustotal_key),
        fetch_github_subdomains(domain, github_token),
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    all_subdomains = set()
    for result in results:
        if isinstance(result, list):
            all_subdomains.update(result)
        elif isinstance(result, Exception):
            console.print(f"[red][!] Passive source error: {result}[/red]")
    
    console.print(f"[bold green][★] Passive sources: {len(all_subdomains)} unique subdomains[/bold green]")
    return list(all_subdomains)
