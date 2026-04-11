"""
core/scan/fuzzer.py — Directory & Parameter Fuzzer
====================================================
Wrappers cho:
  - ffuf  → directory + vhost + parameter fuzzing
  - dirsearch → directory brute-force

Tự động chọn wordlist: custom (từ wordlist_gen) → SecLists fallback.
"""

import asyncio
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# =============================================================================
# Data Model
# =============================================================================

@dataclass
class FuzzResult:
    url: str
    status_code: int
    content_length: int
    words: int
    lines: int
    tool: str
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def is_interesting(self) -> bool:
        """Lọc bỏ 404/default trả về — giữ lại những gì đáng chú ý."""
        return self.status_code in {200, 201, 301, 302, 401, 403, 500}


# =============================================================================
# Helpers
# =============================================================================

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


def _pick_wordlist(domain: str, wordlist_type: str = "paths") -> str:
    """
    Ưu tiên wordlist custom được gen bởi wordlist_gen.py.
    Fallback về SecLists nếu không có.
    """
    custom_path = Path(f"wordlists/{domain}_{wordlist_type}.txt")
    if custom_path.exists():
        return str(custom_path)

    # Common SecLists fallback paths (Linux)
    seclists_candidates = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/opt/SecLists/Discovery/Web-Content/common.txt",
    ]
    for path in seclists_candidates:
        if os.path.exists(path):
            return path

    # Last resort: tiny built-in wordlist
    return _write_builtin_wordlist()


def _write_builtin_wordlist() -> str:
    """Write a minimal built-in wordlist to /tmp when nothing else is available."""
    paths = [
        "admin", "login", "api", "v1", "v2", "v3",
        ".env", ".git", "config", "backup", "test",
        "debug", "info", "health", "status", "metrics",
        "users", "user", "dashboard", "panel", "manage",
        "upload", "uploads", "files", "static", "assets",
    ]
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.write("\n".join(paths))
    tmp.close()
    console.print("[yellow][!] No wordlist found — using built-in minimal list[/yellow]")
    return tmp.name


# =============================================================================
# ffuf
# =============================================================================

async def run_ffuf_dirs(
    url: str,
    wordlist: str | None = None,
    rate: int = 50,
    extensions: str = "php,html,txt,json,js,bak",
    timeout_secs: int = 300,
) -> list[FuzzResult]:
    """
    Directory brute-force với ffuf.
    url phải có FUZZ placeholder, nếu không method tự thêm vào.
    """
    if not _tool_available("ffuf"):
        console.print("[yellow][!] ffuf not installed — skipping directory fuzzing[/yellow]")
        return []

    domain = url.split("//")[-1].split("/")[0]
    wordlist = wordlist or _pick_wordlist(domain, "paths")
    fuzz_url = url.rstrip("/") + "/FUZZ" if "FUZZ" not in url else url

    tmp_out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp_out.close()

    cmd = (
        f"ffuf -u \"{fuzz_url}\" -w \"{wordlist}\" "
        f"-e .{extensions.replace(',', ',.')} "
        f"-rate {rate} -t 40 -timeout 10 "
        f"-mc 200,201,301,302,401,403,500 "
        f"-o {tmp_out.name} -of json -s"
    )

    console.print(f"[cyan][→] ffuf directory fuzzing: {fuzz_url}[/cyan]")
    await _run_cmd(cmd, timeout=timeout_secs)

    results: list[FuzzResult] = []
    try:
        with open(tmp_out.name, encoding="utf-8") as f:
            data = json.load(f)
        for item in data.get("results", []):
            results.append(FuzzResult(
                url=item.get("url", ""),
                status_code=item.get("status", 0),
                content_length=item.get("length", 0),
                words=item.get("words", 0),
                lines=item.get("lines", 0),
                tool="ffuf",
            ))
    except (json.JSONDecodeError, FileNotFoundError):
        pass
    finally:
        os.unlink(tmp_out.name)

    interesting = [r for r in results if r.is_interesting()]
    console.print(f"[green][✓] ffuf: {len(interesting)} interesting paths found at {domain}[/green]")
    return interesting


async def run_ffuf_vhosts(
    base_url: str,
    domain: str,
    wordlist: str | None = None,
    rate: int = 100,
) -> list[FuzzResult]:
    """
    Virtual-host brute-force với ffuf.
    Tìm subdomain ẩn không có trong DNS.
    """
    if not _tool_available("ffuf"):
        console.print("[yellow][!] ffuf not installed — skipping vhost fuzzing[/yellow]")
        return []

    wordlist = wordlist or _pick_wordlist(domain, "subdomains")
    tmp_out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp_out.close()

    cmd = (
        f"ffuf -u \"{base_url}\" "
        f"-H \"Host: FUZZ.{domain}\" "
        f"-w \"{wordlist}\" "
        f"-rate {rate} -t 50 "
        f"-mc 200,301,302,401,403 "
        f"-o {tmp_out.name} -of json -s"
    )

    console.print(f"[cyan][→] ffuf vhost fuzzing for *.{domain}[/cyan]")
    await _run_cmd(cmd, timeout=300)

    results: list[FuzzResult] = []
    try:
        with open(tmp_out.name) as f:
            data = json.load(f)
        for item in data.get("results", []):
            results.append(FuzzResult(
                url=f"{item.get('input', {}).get('FUZZ', '?')}.{domain}",
                status_code=item.get("status", 0),
                content_length=item.get("length", 0),
                words=item.get("words", 0),
                lines=item.get("lines", 0),
                tool="ffuf-vhost",
            ))
    except (json.JSONDecodeError, FileNotFoundError):
        pass
    finally:
        os.unlink(tmp_out.name)

    console.print(f"[green][✓] ffuf vhost: {len(results)} vhost(s) found for {domain}[/green]")
    return results


# =============================================================================
# dirsearch
# =============================================================================

async def run_dirsearch(
    url: str,
    extensions: str = "php,html,txt,js,json,bak",
    threads: int = 20,
    timeout_secs: int = 300,
) -> list[FuzzResult]:
    """
    dirsearch fallback — dùng khi ffuf không có.
    """
    if not _tool_available("dirsearch"):
        console.print("[yellow][!] dirsearch not installed — skipping[/yellow]")
        return []

    tmp_out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp_out.close()

    cmd = (
        f"dirsearch -u \"{url}\" -e {extensions} "
        f"-t {threads} --format json -o {tmp_out.name} -q"
    )

    console.print(f"[cyan][→] dirsearch: {url}[/cyan]")
    await _run_cmd(cmd, timeout=timeout_secs)

    results: list[FuzzResult] = []
    try:
        with open(tmp_out.name) as f:
            data = json.load(f)
        for item in data.get("results", []):
            results.append(FuzzResult(
                url=item.get("url", ""),
                status_code=item.get("status", 0),
                content_length=item.get("content-length", 0),
                words=0,
                lines=0,
                tool="dirsearch",
            ))
    except (json.JSONDecodeError, FileNotFoundError):
        pass
    finally:
        os.unlink(tmp_out.name)

    interesting = [r for r in results if r.is_interesting()]
    console.print(f"[green][✓] dirsearch: {len(interesting)} paths found[/green]")
    return interesting


# =============================================================================
# Orchestrator
# =============================================================================

async def run_fuzzing_pipeline(
    hosts: list[str],
    domain: str,
    run_vhost: bool = True,
) -> list[FuzzResult]:
    """
    Chạy directory + vhost fuzzing cho tất cả alive hosts.
    Tự chọn ffuf hoặc dirsearch tuỳ cái nào có sẵn.
    """
    all_results: list[FuzzResult] = []
    use_ffuf = _tool_available("ffuf")

    tasks = []
    for host in hosts:
        if use_ffuf:
            tasks.append(run_ffuf_dirs(host))
        else:
            tasks.append(run_dirsearch(host))

    if run_vhost and hosts and use_ffuf:
        base = hosts[0]
        tasks.append(run_ffuf_vhosts(base, domain))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            all_results.extend(r)
        elif isinstance(r, Exception):
            console.print(f"[red][!] Fuzzer error: {r}[/red]")

    console.print(f"\n[bold green][★] Fuzzing complete: {len(all_results)} total paths[/bold green]")
    return all_results
