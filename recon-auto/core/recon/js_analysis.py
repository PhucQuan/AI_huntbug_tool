"""
core/recon/js_analysis.py — JavaScript File Analysis
=====================================================
Phân tích JS files để tìm:
  - Hidden endpoints
  - API keys
  - Secrets
  - Internal paths
"""

import asyncio
import re
from typing import List, Dict, Set

import httpx
from rich.console import Console

console = Console()


# =============================================================================
# Regex Patterns
# =============================================================================

ENDPOINT_PATTERNS = [
    r'/(?:api|v[0-9]+)/[a-z0-9\-/]+',
    r'fetch\([\'"`]([^\'"` ]+)[\'"`]\)',
    r'axios\.\w+\([\'"`]([^\'"` ]+)[\'"`]\)',
    r'\.get\([\'"`]([^\'"` ]+)[\'"`]\)',
    r'\.post\([\'"`]([^\'"` ]+)[\'"`]\)',
    r'url:\s*[\'"`]([^\'"` ]+)[\'"`]',
    r'endpoint:\s*[\'"`]([^\'"` ]+)[\'"`]',
]

SECRET_PATTERNS = {
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key": r'aws_secret_key|aws_secret_access_key',
    "API Key": r'api[_-]?key[\'":\s]+[\'"]([a-zA-Z0-9_\-]{20,})[\'"]',
    "Password": r'password[\'":\s]+[\'"]([^\'"]{8,})[\'"]',
    "Token": r'token[\'":\s]+[\'"]([a-zA-Z0-9_\-\.]{20,})[\'"]',
    "JWT": r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
    "Private Key": r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    "Slack Token": r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    "GitHub Token": r'gh[pousr]_[0-9a-zA-Z]{36}',
    "Google API": r'AIza[0-9A-Za-z\-_]{35}',
    "Firebase": r'firebase[_-]?api[_-]?key',
    "Heroku API": r'heroku[_-]?api[_-]?key',
    "Stripe": r'sk_live_[0-9a-zA-Z]{24}',
    "Twilio": r'SK[0-9a-fA-F]{32}',
}

SUBDOMAIN_PATTERNS = [
    r'https?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})',
    r'//([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})',
]


# =============================================================================
# JS Content Fetching
# =============================================================================

async def fetch_js_content(url: str) -> str:
    """Fetch nội dung của JS file."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.text
    except Exception as e:
        console.print(f"[!] Failed to fetch {url}: {e}")
    return ""


# =============================================================================
# Endpoint Extraction
# =============================================================================

def extract_endpoints(js_content: str) -> List[str]:
    """Extract API endpoints từ JS content."""
    endpoints = set()
    
    for pattern in ENDPOINT_PATTERNS:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            if match and len(match) > 3:
                endpoints.add(match)
    
    return list(endpoints)


# =============================================================================
# Secret Detection
# =============================================================================

def detect_secrets(js_content: str) -> Dict[str, List[str]]:
    """Detect secrets và sensitive data trong JS."""
    findings = {}
    
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        if matches:
            findings[secret_type] = matches
    
    return findings


# =============================================================================
# Subdomain Extraction
# =============================================================================

def extract_subdomains(js_content: str, base_domain: str) -> List[str]:
    """Extract subdomains từ JS content."""
    subdomains = set()
    
    for pattern in SUBDOMAIN_PATTERNS:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            if base_domain in match:
                subdomains.add(match)
    
    return list(subdomains)


# =============================================================================
# Comments & Debug Info
# =============================================================================

def extract_comments(js_content: str) -> List[str]:
    """Extract comments từ JS (có thể chứa thông tin nhạy cảm)."""
    # Single-line comments
    single_line = re.findall(r'//(.+)', js_content)
    
    # Multi-line comments
    multi_line = re.findall(r'/\*(.+?)\*/', js_content, re.DOTALL)
    
    all_comments = single_line + multi_line
    
    # Filter comments có keywords nhạy cảm
    sensitive_keywords = ['password', 'secret', 'key', 'token', 'api', 'admin', 'debug', 'todo', 'fixme']
    sensitive_comments = []
    
    for comment in all_comments:
        comment_lower = comment.lower()
        if any(keyword in comment_lower for keyword in sensitive_keywords):
            sensitive_comments.append(comment.strip())
    
    return sensitive_comments


# =============================================================================
# Full JS Analysis
# =============================================================================

async def analyze_js_file(url: str, base_domain: str = None) -> Dict:
    """
    Phân tích đầy đủ một JS file.
    """
    console.print(f"[→] Analyzing JS: {url}")
    
    content = await fetch_js_content(url)
    if not content:
        return None
    
    result = {
        "url": url,
        "size": len(content),
        "endpoints": extract_endpoints(content),
        "secrets": detect_secrets(content),
        "comments": extract_comments(content),
    }
    
    if base_domain:
        result["subdomains"] = extract_subdomains(content, base_domain)
    
    # Summary
    if result["secrets"]:
        console.print(f"[red][!] SECRETS FOUND in {url}:[/red]")
        for secret_type, values in result["secrets"].items():
            console.print(f"  - {secret_type}: {len(values)} found")
    
    if result["endpoints"]:
        console.print(f"[green][✓] {len(result['endpoints'])} endpoints found in {url}[/green]")
    
    return result


async def analyze_js_files_bulk(
    js_urls: List[str],
    base_domain: str = None,
    max_files: int = 50,
) -> List[Dict]:
    """Phân tích nhiều JS files song song."""
    console.print(f"[cyan][→] Analyzing {min(max_files, len(js_urls))} JS files...[/cyan]")
    
    tasks = [analyze_js_file(url, base_domain) for url in js_urls[:max_files]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    valid_results = []
    for result in results:
        if isinstance(result, dict):
            valid_results.append(result)
        elif isinstance(result, Exception):
            console.print(f"[!] JS analysis error: {result}")
    
    return valid_results


# =============================================================================
# Orchestrator
# =============================================================================

async def run_js_analysis_pipeline(
    js_urls: List[str],
    base_domain: str = None,
    max_files: int = 50,
) -> Dict:
    """
    Chạy JS analysis pipeline.
    """
    console.print(f"[cyan][→] Starting JS analysis on {len(js_urls)} files...[/cyan]")
    
    results = await analyze_js_files_bulk(js_urls, base_domain, max_files)
    
    # Aggregate findings
    all_endpoints = set()
    all_secrets = {}
    all_subdomains = set()
    all_comments = []
    
    for result in results:
        all_endpoints.update(result.get("endpoints", []))
        
        for secret_type, values in result.get("secrets", {}).items():
            if secret_type not in all_secrets:
                all_secrets[secret_type] = []
            all_secrets[secret_type].extend(values)
        
        all_subdomains.update(result.get("subdomains", []))
        all_comments.extend(result.get("comments", []))
    
    console.print(f"\n[bold green][★] JS Analysis Summary:[/bold green]")
    console.print(f"  Files analyzed: {len(results)}")
    console.print(f"  Endpoints found: {len(all_endpoints)}")
    console.print(f"  Secrets found: {sum(len(v) for v in all_secrets.values())}")
    console.print(f"  Subdomains found: {len(all_subdomains)}")
    console.print(f"  Sensitive comments: {len(all_comments)}")
    
    return {
        "results": results,
        "all_endpoints": list(all_endpoints),
        "all_secrets": all_secrets,
        "all_subdomains": list(all_subdomains),
        "all_comments": all_comments,
    }
