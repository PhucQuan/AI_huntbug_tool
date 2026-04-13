"""
core/recon/url_collection.py — URL Discovery & Collection
==========================================================
Thu thập URLs từ:
  - gau (getallurls) — passive crawling
  - katana — active crawling
  - hakrawler — active crawling
  - urlfinder — passive URLs
"""

import asyncio
import os
import re
import shutil
import tempfile
from typing import List, Set

from rich.console import Console

console = Console()


def _tool_available(name: str) -> bool:
    """Check nếu tool có trong PATH."""
    return shutil.which(name) is not None


async def _run_cmd(cmd: str, timeout: int = 300) -> tuple[str, str]:
    """Run command async, return (stdout, stderr)."""
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
# gau — getallurls (Passive)
# =============================================================================

async def run_gau(domains: List[str]) -> List[str]:
    """
    Chạy gau để lấy URLs từ Wayback, OTX, Common Crawl.
    Install: go install github.com/lc/gau/v2/cmd/gau@latest
    """
    if not _tool_available("gau"):
        console.print("[yellow][!] gau not installed — skipping[/yellow]")
        return []
    
    # Ghi domains vào temp file
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.write("\n".join(domains))
    tmp.close()
    
    try:
        cmd = f"cat {tmp.name} | gau --threads 5 --mc 200"
        stdout, _ = await _run_cmd(cmd, timeout=180)
        
        urls = [line.strip() for line in stdout.splitlines() if line.strip()]
        console.print(f"[green][✓] gau: {len(urls)} URLs[/green]")
        return urls
    finally:
        os.unlink(tmp.name)


# =============================================================================
# katana — Active Crawler
# =============================================================================

async def run_katana(domains: List[str], depth: int = 2) -> List[str]:
    """
    Chạy katana để crawl URLs.
    Install: go install github.com/projectdiscovery/katana/cmd/katana@latest
    """
    if not _tool_available("katana"):
        console.print("[yellow][!] katana not installed — skipping[/yellow]")
        return []
    
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.write("\n".join(domains))
    tmp.close()
    
    try:
        cmd = f"katana -list {tmp.name} -d {depth} -jc -kf all -silent"
        stdout, _ = await _run_cmd(cmd, timeout=300)
        
        urls = [line.strip() for line in stdout.splitlines() if line.strip()]
        console.print(f"[green][✓] katana: {len(urls)} URLs[/green]")
        return urls
    finally:
        os.unlink(tmp.name)


# =============================================================================
# hakrawler — Active Crawler
# =============================================================================

async def run_hakrawler(domains: List[str]) -> List[str]:
    """
    Chạy hakrawler.
    Install: go install github.com/hakluke/hakrawler@latest
    """
    if not _tool_available("hakrawler"):
        console.print("[yellow][!] hakrawler not installed — skipping[/yellow]")
        return []
    
    all_urls = []
    for domain in domains[:10]:  # Limit để tránh quá lâu
        cmd = f"echo {domain} | hakrawler -d 2 -u"
        stdout, _ = await _run_cmd(cmd, timeout=60)
        urls = [line.strip() for line in stdout.splitlines() if line.strip()]
        all_urls.extend(urls)
    
    console.print(f"[green][✓] hakrawler: {len(all_urls)} URLs[/green]")
    return all_urls


# =============================================================================
# urlfinder — Passive URLs
# =============================================================================

async def run_urlfinder(domain: str) -> List[str]:
    """
    Chạy urlfinder.
    Install: go install github.com/projectdiscovery/urlfinder@latest
    """
    if not _tool_available("urlfinder"):
        console.print("[yellow][!] urlfinder not installed — skipping[/yellow]")
        return []
    
    cmd = f"urlfinder -d {domain}"
    stdout, _ = await _run_cmd(cmd, timeout=120)
    
    urls = [line.strip() for line in stdout.splitlines() if line.strip()]
    console.print(f"[green][✓] urlfinder: {len(urls)} URLs[/green]")
    return urls


# =============================================================================
# URL Filtering & Deduplication
# =============================================================================

def filter_urls_with_params(urls: List[str]) -> List[str]:
    """Lọc chỉ giữ URLs có parameters (chứa '=')."""
    return [url for url in urls if '=' in url]


def filter_sensitive_files(urls: List[str]) -> List[str]:
    """Lọc URLs chứa sensitive file extensions."""
    extensions = [
        r'\.xls', r'\.xml', r'\.xlsx', r'\.json', r'\.pdf', r'\.sql',
        r'\.doc', r'\.docx', r'\.pptx', r'\.txt', r'\.zip', r'\.tar\.gz',
        r'\.tgz', r'\.bak', r'\.7z', r'\.rar', r'\.log', r'\.cache',
        r'\.secret', r'\.db', r'\.backup', r'\.yml', r'\.gz', r'\.config',
        r'\.csv', r'\.yaml', r'\.md', r'\.md5', r'\.env', r'\.key',
        r'\.pem', r'\.crt', r'\.p12'
    ]
    pattern = '|'.join(extensions)
    regex = re.compile(pattern, re.IGNORECASE)
    return [url for url in urls if regex.search(url)]


def filter_js_files(urls: List[str]) -> List[str]:
    """Lọc chỉ giữ JavaScript files."""
    return [url for url in urls if url.endswith('.js')]


def deduplicate_urls(urls: List[str]) -> List[str]:
    """Deduplicate URLs."""
    return list(set(urls))


# =============================================================================
# Orchestrator
# =============================================================================

async def run_url_collection_pipeline(
    domains: List[str],
    run_active: bool = True,
    run_passive: bool = True,
) -> dict:
    """
    Chạy toàn bộ URL collection pipeline.
    Returns dict với các loại URLs đã phân loại.
    """
    console.print(f"[cyan][→] Starting URL collection for {len(domains)} domains...[/cyan]")
    
    tasks = []
    
    if run_passive:
        tasks.append(run_gau(domains))
        if len(domains) == 1:
            tasks.append(run_urlfinder(domains[0]))
    
    if run_active:
        tasks.append(run_katana(domains))
        tasks.append(run_hakrawler(domains))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    all_urls: Set[str] = set()
    for result in results:
        if isinstance(result, list):
            all_urls.update(result)
        elif isinstance(result, Exception):
            console.print(f"[red][!] URL collection error: {result}[/red]")
    
    all_urls_list = list(all_urls)
    
    # Phân loại URLs
    urls_with_params = filter_urls_with_params(all_urls_list)
    sensitive_files = filter_sensitive_files(all_urls_list)
    js_files = filter_js_files(all_urls_list)
    
    console.print(f"\n[bold green][★] URL Collection Summary:[/bold green]")
    console.print(f"  Total URLs: {len(all_urls_list)}")
    console.print(f"  With params: {len(urls_with_params)}")
    console.print(f"  Sensitive files: {len(sensitive_files)}")
    console.print(f"  JS files: {len(js_files)}")
    
    return {
        "all_urls": all_urls_list,
        "urls_with_params": urls_with_params,
        "sensitive_files": sensitive_files,
        "js_files": js_files,
    }
