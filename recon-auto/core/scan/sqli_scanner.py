"""
core/scan/sqli_scanner.py — SQL Injection Detection
====================================================
Detect SQL injection vulnerabilities bằng:
  - sqlmap — automated SQLi detection & exploitation
  - Manual pattern-based detection
"""

import asyncio
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from typing import List, Dict

from rich.console import Console

console = Console()


@dataclass
class SQLiResult:
    url: str
    parameter: str
    injection_type: str
    dbms: str
    payload: str
    vulnerable: bool
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
# Technology Detection — Filter SQLi-prone endpoints
# =============================================================================

def filter_sqli_prone_urls(urls: List[str]) -> List[str]:
    """
    Lọc URLs có khả năng vulnerable với SQLi dựa trên:
    - File extensions: .php, .asp, .aspx, .jsp, .jspx
    - Parameters: id, select, query, user, etc.
    """
    sqli_extensions = [r'\.php', r'\.asp', r'\.aspx', r'\.jsp', r'\.jspx']
    sqli_params = [
        'id', 'select', 'report', 'role', 'update', 'query', 'user',
        'name', 'sort', 'where', 'search', 'params', 'process', 'row',
        'view', 'table', 'from', 'sel', 'results', 'sleep', 'fetch',
        'order', 'keyword', 'column', 'field', 'delete', 'string',
        'number', 'filter'
    ]
    
    ext_pattern = '|'.join(sqli_extensions)
    param_pattern = '|'.join([f'{p}=' for p in sqli_params])
    
    ext_regex = re.compile(ext_pattern, re.IGNORECASE)
    param_regex = re.compile(param_pattern, re.IGNORECASE)
    
    filtered = []
    for url in urls:
        if ext_regex.search(url) and param_regex.search(url):
            filtered.append(url)
    
    console.print(f"[green][✓] Filtered {len(filtered)} SQLi-prone URLs[/green]")
    return filtered


# =============================================================================
# sqlmap — Automated SQLi Scanner
# =============================================================================

async def run_sqlmap(
    url: str,
    level: int = 1,
    risk: int = 1,
    batch: bool = True,
    threads: int = 5,
    timeout_mins: int = 5,
) -> List[SQLiResult]:
    """
    Chạy sqlmap để detect SQLi.
    Install: apt install sqlmap hoặc pip install sqlmap-dev
    """
    if not _tool_available("sqlmap"):
        console.print("[yellow][!] sqlmap not installed — skipping[/yellow]")
        return []
    
    tmp_output = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp_output.close()
    
    try:
        cmd_parts = [
            f"sqlmap -u \"{url}\"",
            f"--level={level}",
            f"--risk={risk}",
            f"--threads={threads}",
            "--random-agent",
            f"-o {tmp_output.name}",
        ]
        
        if batch:
            cmd_parts.append("--batch")
        
        cmd = " ".join(cmd_parts)
        console.print(f"[cyan][→] Running sqlmap on {url}...[/cyan]")
        
        stdout, stderr = await _run_cmd(cmd, timeout=timeout_mins * 60)
        
        # Parse sqlmap output
        results = []
        
        # sqlmap không có JSON output chuẩn, parse từ stdout
        if "is vulnerable" in stdout.lower() or "injectable" in stdout.lower():
            # Extract thông tin cơ bản
            param_match = re.search(r"Parameter: (\w+)", stdout)
            dbms_match = re.search(r"back-end DBMS: (\w+)", stdout, re.IGNORECASE)
            injection_match = re.search(r"Type: (.+)", stdout)
            
            results.append(SQLiResult(
                url=url,
                parameter=param_match.group(1) if param_match else "unknown",
                injection_type=injection_match.group(1).strip() if injection_match else "unknown",
                dbms=dbms_match.group(1) if dbms_match else "unknown",
                payload="",
                vulnerable=True,
                tool="sqlmap",
            ))
        
        if results:
            console.print(f"[red][!] SQLi FOUND: {url}[/red]")
        else:
            console.print(f"[green][✓] sqlmap: No SQLi found in {url}[/green]")
        
        return results
        
    finally:
        if os.path.exists(tmp_output.name):
            os.unlink(tmp_output.name)


async def run_sqlmap_bulk(
    urls: List[str],
    max_urls: int = 20,
    level: int = 1,
    risk: int = 1,
) -> List[SQLiResult]:
    """Chạy sqlmap trên nhiều URLs (giới hạn để tránh quá lâu)."""
    all_results = []
    
    for url in urls[:max_urls]:
        results = await run_sqlmap(url, level=level, risk=risk, timeout_mins=3)
        all_results.extend(results)
    
    return all_results


# =============================================================================
# Manual SQLi Detection — Pattern-based
# =============================================================================

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL--",
    "1' AND SLEEP(5)--",
    "1' WAITFOR DELAY '0:0:5'--",
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*pg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.*SQL.*Server",
    r"OLE DB.*SQL Server",
    r"SQLServer JDBC Driver",
    r"SqlException",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*oci_",
    r"Warning.*ora_",
]


async def test_sqli_manual(url: str) -> SQLiResult:
    """
    Test SQLi thủ công bằng cách inject payloads và check error messages.
    """
    import httpx
    
    # Chỉ test nếu URL có parameter
    if '=' not in url:
        return None
    
    # Extract parameter
    param_match = re.search(r'([?&])(\w+)=([^&]*)', url)
    if not param_match:
        return None
    
    separator, param_name, param_value = param_match.groups()
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        for payload in SQLI_PAYLOADS[:3]:  # Test 3 payloads đầu
            try:
                # Inject payload
                test_url = url.replace(
                    f"{separator}{param_name}={param_value}",
                    f"{separator}{param_name}={payload}"
                )
                
                resp = await client.get(test_url)
                body = resp.text
                
                # Check for SQL error patterns
                for pattern in SQLI_ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        return SQLiResult(
                            url=url,
                            parameter=param_name,
                            injection_type="error-based",
                            dbms="unknown",
                            payload=payload,
                            vulnerable=True,
                            tool="manual",
                        )
                
            except Exception:
                continue
    
    return None


async def run_manual_sqli_bulk(urls: List[str], max_urls: int = 50) -> List[SQLiResult]:
    """Chạy manual SQLi test trên nhiều URLs."""
    console.print(f"[cyan][→] Running manual SQLi tests on {min(max_urls, len(urls))} URLs...[/cyan]")
    
    tasks = [test_sqli_manual(url) for url in urls[:max_urls]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    vulnerable = []
    for result in results:
        if isinstance(result, SQLiResult) and result.vulnerable:
            vulnerable.append(result)
    
    console.print(f"[green][✓] Manual SQLi: {len(vulnerable)} vulnerabilities found[/green]")
    return vulnerable


# =============================================================================
# Orchestrator
# =============================================================================

async def run_sqli_scan_pipeline(
    urls: List[str],
    use_sqlmap: bool = False,
    use_manual: bool = True,
    max_sqlmap_urls: int = 10,
    max_manual_urls: int = 50,
) -> Dict[str, List[SQLiResult]]:
    """
    Chạy SQL injection detection pipeline.
    
    Returns:
        {
            "filtered_urls": [...],
            "sqlmap_results": [...],
            "manual_results": [...]
        }
    """
    console.print(f"[cyan][→] Starting SQLi scan on {len(urls)} URLs...[/cyan]")
    
    # 1. Filter SQLi-prone URLs
    filtered_urls = filter_sqli_prone_urls(urls)
    
    if not filtered_urls:
        console.print("[yellow][!] No SQLi-prone URLs found[/yellow]")
        return {
            "filtered_urls": [],
            "sqlmap_results": [],
            "manual_results": [],
        }
    
    results = {
        "filtered_urls": filtered_urls,
        "sqlmap_results": [],
        "manual_results": [],
    }
    
    # 2. Manual testing (fast)
    if use_manual:
        results["manual_results"] = await run_manual_sqli_bulk(
            filtered_urls,
            max_urls=max_manual_urls
        )
    
    # 3. sqlmap (slow, chỉ chạy nếu được yêu cầu)
    if use_sqlmap:
        results["sqlmap_results"] = await run_sqlmap_bulk(
            filtered_urls,
            max_urls=max_sqlmap_urls
        )
    
    total_vulns = len(results["sqlmap_results"]) + len(results["manual_results"])
    console.print(f"\n[bold green][★] SQLi Scan Summary: {total_vulns} vulnerabilities found[/bold green]")
    
    return results
