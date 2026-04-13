"""
core/scan/git_exposure.py — .git Directory Exposure Detection
==============================================================
Detect exposed .git directories và extract sensitive data.
"""

import asyncio
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from typing import List, Dict

import httpx
from rich.console import Console

console = Console()


@dataclass
class GitExposureResult:
    url: str
    exposed: bool
    has_index: bool
    has_config: bool
    has_head: bool
    sensitive_files: List[str]
    tool: str


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
# Manual .git Detection
# =============================================================================

GIT_PATHS = [
    "/.git/",
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.git/refs/heads/master",
    "/.git/refs/heads/main",
]


async def check_git_exposure(base_url: str) -> GitExposureResult:
    """
    Check nếu .git directory bị exposed.
    """
    # Normalize URL
    base_url = base_url.rstrip('/')
    
    result = GitExposureResult(
        url=base_url,
        exposed=False,
        has_index=False,
        has_config=False,
        has_head=False,
        sensitive_files=[],
        tool="manual",
    )
    
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        for path in GIT_PATHS:
            try:
                test_url = f"{base_url}{path}"
                resp = await client.get(test_url)
                
                # Check nếu file tồn tại
                if resp.status_code == 200:
                    result.exposed = True
                    result.sensitive_files.append(path)
                    
                    # Check specific files
                    if "/.git/index" in path:
                        result.has_index = True
                    elif "/.git/config" in path:
                        result.has_config = True
                    elif "/.git/HEAD" in path:
                        result.has_head = True
                
                # Check directory listing
                elif resp.status_code in [301, 302] and "/.git/" == path:
                    location = resp.headers.get("Location", "")
                    if "/.git/" in location:
                        result.exposed = True
                        result.sensitive_files.append(path)
                
            except Exception:
                continue
    
    if result.exposed:
        console.print(f"[red][!] .git EXPOSED: {base_url}[/red]")
    
    return result


async def check_git_exposure_bulk(urls: List[str]) -> List[GitExposureResult]:
    """Check .git exposure trên nhiều URLs."""
    console.print(f"[cyan][→] Checking .git exposure on {len(urls)} URLs...[/cyan]")
    
    tasks = [check_git_exposure(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    exposed = []
    for result in results:
        if isinstance(result, GitExposureResult) and result.exposed:
            exposed.append(result)
    
    console.print(f"[green][✓] .git exposure: {len(exposed)} exposed repositories found[/green]")
    return exposed


# =============================================================================
# git-dumper — Automated .git Extraction
# =============================================================================

async def run_git_dumper(url: str, output_dir: str = None) -> bool:
    """
    Chạy git-dumper để extract .git repository.
    Install: pip install git-dumper
    """
    if not _tool_available("git-dumper"):
        console.print("[yellow][!] git-dumper not installed — skipping[/yellow]")
        return False
    
    if not output_dir:
        output_dir = tempfile.mkdtemp(prefix="git_dump_")
    
    git_url = url.rstrip('/') + '/.git/'
    
    try:
        cmd = f"git-dumper {git_url} {output_dir}"
        console.print(f"[cyan][→] Running git-dumper on {url}...[/cyan]")
        
        stdout, stderr = await _run_cmd(cmd, timeout=120)
        
        # Check nếu dump thành công
        if os.path.exists(os.path.join(output_dir, ".git")):
            console.print(f"[green][✓] git-dumper: Successfully dumped to {output_dir}[/green]")
            
            # List sensitive files
            await list_sensitive_files_in_repo(output_dir)
            return True
        else:
            console.print(f"[yellow][!] git-dumper: Failed to dump {url}[/yellow]")
            return False
            
    except Exception as e:
        console.print(f"[!] git-dumper error: {e}")
        return False


async def list_sensitive_files_in_repo(repo_path: str):
    """
    List các file nhạy cảm trong dumped repo.
    """
    sensitive_patterns = [
        r'\.env',
        r'\.key',
        r'\.pem',
        r'\.p12',
        r'\.pfx',
        r'config\.php',
        r'config\.yml',
        r'config\.yaml',
        r'database\.yml',
        r'credentials',
        r'secret',
        r'password',
        r'token',
        r'api[_-]?key',
    ]
    
    console.print(f"[→] Scanning for sensitive files in {repo_path}...")
    
    sensitive_files = []
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            file_lower = file.lower()
            for pattern in sensitive_patterns:
                if re.search(pattern, file_lower, re.IGNORECASE):
                    file_path = os.path.join(root, file)
                    sensitive_files.append(file_path)
                    break
    
    if sensitive_files:
        console.print(f"[red][!] Found {len(sensitive_files)} sensitive files:[/red]")
        for f in sensitive_files[:10]:  # Show first 10
            console.print(f"  - {f}")
    else:
        console.print("[green][✓] No obvious sensitive files found[/green]")


# =============================================================================
# GitTools — Alternative extraction tool
# =============================================================================

async def run_gittools(url: str, output_dir: str = None) -> bool:
    """
    Chạy GitTools/Dumper để extract .git.
    Install: git clone https://github.com/internetwache/GitTools.git
    """
    gittools_path = shutil.which("gitdumper.sh")
    if not gittools_path:
        console.print("[yellow][!] GitTools not installed — skipping[/yellow]")
        return False
    
    if not output_dir:
        output_dir = tempfile.mkdtemp(prefix="git_dump_")
    
    git_url = url.rstrip('/') + '/.git/'
    
    try:
        cmd = f"{gittools_path} {git_url} {output_dir}"
        console.print(f"[cyan][→] Running GitTools on {url}...[/cyan]")
        
        await _run_cmd(cmd, timeout=120)
        
        if os.path.exists(os.path.join(output_dir, ".git")):
            console.print(f"[green][✓] GitTools: Successfully dumped to {output_dir}[/green]")
            return True
        else:
            return False
            
    except Exception as e:
        console.print(f"[!] GitTools error: {e}")
        return False


# =============================================================================
# Orchestrator
# =============================================================================

async def run_git_exposure_pipeline(
    urls: List[str],
    extract_repos: bool = False,
    output_dir: str = "git_dumps",
) -> Dict[str, any]:
    """
    Chạy .git exposure detection pipeline.
    
    extract_repos: Nếu True, sẽ dump exposed repos
    """
    console.print(f"[cyan][→] Starting .git exposure scan on {len(urls)} URLs...[/cyan]")
    
    # 1. Check exposure
    exposed_results = await check_git_exposure_bulk(urls)
    
    # 2. Extract repos (optional)
    extracted = []
    if extract_repos and exposed_results:
        os.makedirs(output_dir, exist_ok=True)
        
        for result in exposed_results[:5]:  # Limit 5 để demo
            repo_dir = os.path.join(output_dir, result.url.replace("https://", "").replace("http://", "").replace("/", "_"))
            success = await run_git_dumper(result.url, repo_dir)
            if success:
                extracted.append(repo_dir)
    
    console.print(f"\n[bold red][★] .git Exposure Summary:[/bold red]")
    console.print(f"  Exposed repos: {len(exposed_results)}")
    console.print(f"  Extracted repos: {len(extracted)}")
    
    return {
        "exposed_results": exposed_results,
        "extracted_repos": extracted,
    }
