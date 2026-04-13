#!/usr/bin/env python3
"""
check_tools.py — Tool Dependency Checker
=========================================
Check xem tất cả external tools đã được cài đặt chưa.
Chạy script này TRƯỚC KHI chạy recon để biết tool nào còn thiếu.

Usage:
    python check_tools.py
    python check_tools.py --fix  # Show installation commands
"""

import shutil
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# =============================================================================
# Tool Dependencies
# =============================================================================

REQUIRED_TOOLS = {
    "Core Recon": {
        "subfinder": {
            "required": True,
            "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "description": "Subdomain enumeration"
        },
        "httpx": {
            "required": True,
            "install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "description": "HTTP probe & tech detection"
        },
    },
    
    "Subdomain Discovery": {
        "amass": {
            "required": False,
            "install": "go install github.com/owasp-amass/amass/v4/...@master",
            "description": "Advanced subdomain enum"
        },
        "assetfinder": {
            "required": False,
            "install": "go install github.com/tomnomnom/assetfinder@latest",
            "description": "Subdomain finder"
        },
        "findomain": {
            "required": False,
            "install": "wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux && chmod +x findomain-linux && sudo mv findomain-linux /usr/local/bin/findomain",
            "description": "Fast subdomain enum"
        },
    },
    
    "URL Collection": {
        "gau": {
            "required": False,
            "install": "go install github.com/lc/gau/v2/cmd/gau@latest",
            "description": "Get all URLs (passive)"
        },
        "katana": {
            "required": False,
            "install": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            "description": "Active web crawler"
        },
        "hakrawler": {
            "required": False,
            "install": "go install github.com/hakluke/hakrawler@latest",
            "description": "Fast web crawler"
        },
    },
    
    "Vulnerability Scanning": {
        "nuclei": {
            "required": True,
            "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "description": "Vulnerability scanner"
        },
        "dalfox": {
            "required": False,
            "install": "go install github.com/hahwul/dalfox/v2@latest",
            "description": "XSS scanner"
        },
        "sqlmap": {
            "required": False,
            "install": "sudo apt install sqlmap -y",
            "description": "SQL injection scanner"
        },
        "ffuf": {
            "required": False,
            "install": "go install github.com/ffuf/ffuf/v2@latest",
            "description": "Web fuzzer"
        },
    },
    
    "Port Scanning": {
        "naabu": {
            "required": False,
            "install": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "description": "Fast port scanner"
        },
        "nmap": {
            "required": False,
            "install": "sudo apt install nmap -y",
            "description": "Network scanner"
        },
        "masscan": {
            "required": False,
            "install": "sudo apt install masscan -y",
            "description": "Ultra-fast port scanner"
        },
    },
    
    "Specialized Scanners": {
        "subzy": {
            "required": False,
            "install": "go install github.com/PentestPad/subzy@latest",
            "description": "Subdomain takeover checker"
        },
        "arjun": {
            "required": False,
            "install": "pip install arjun",
            "description": "Parameter discovery"
        },
        "git-dumper": {
            "required": False,
            "install": "pip install git-dumper",
            "description": ".git exposure extractor"
        },
    },
    
    "Optional Tools": {
        "gowitness": {
            "required": False,
            "install": "go install github.com/sensepost/gowitness@latest",
            "description": "Screenshot tool"
        },
        "wafw00f": {
            "required": False,
            "install": "pip install wafw00f",
            "description": "WAF detection"
        },
        "dirsearch": {
            "required": False,
            "install": "pip install dirsearch",
            "description": "Directory brute-force"
        },
    }
}


# =============================================================================
# Checker Functions
# =============================================================================

def check_tool(tool_name: str) -> bool:
    """Check nếu tool có trong PATH."""
    return shutil.which(tool_name) is not None


def check_all_tools() -> dict:
    """
    Check tất cả tools và return status.
    Returns: {category: {tool: {installed: bool, ...}}}
    """
    results = {}
    
    for category, tools in REQUIRED_TOOLS.items():
        results[category] = {}
        for tool_name, tool_info in tools.items():
            installed = check_tool(tool_name)
            results[category][tool_name] = {
                "installed": installed,
                "required": tool_info["required"],
                "install": tool_info["install"],
                "description": tool_info["description"]
            }
    
    return results


def print_results(results: dict, show_fix: bool = False):
    """Print results với Rich formatting."""
    
    # Summary stats
    total_tools = 0
    installed_tools = 0
    required_missing = []
    optional_missing = []
    
    for category, tools in results.items():
        for tool_name, info in tools.items():
            total_tools += 1
            if info["installed"]:
                installed_tools += 1
            else:
                if info["required"]:
                    required_missing.append(tool_name)
                else:
                    optional_missing.append(tool_name)
    
    # Print summary
    console.print("\n")
    console.print(Panel.fit(
        f"[bold cyan]Tool Dependency Check[/bold cyan]\n"
        f"Total: {total_tools} tools | "
        f"[green]Installed: {installed_tools}[/green] | "
        f"[yellow]Missing: {total_tools - installed_tools}[/yellow]",
        border_style="cyan"
    ))
    
    # Print detailed table
    for category, tools in results.items():
        console.print(f"\n[bold magenta]━━━ {category} ━━━[/bold magenta]")
        
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Tool", style="dim")
        table.add_column("Status", justify="center")
        table.add_column("Required", justify="center")
        table.add_column("Description")
        
        for tool_name, info in tools.items():
            status = "[green]✓ Installed[/green]" if info["installed"] else "[red]✗ Missing[/red]"
            required = "[red]Yes[/red]" if info["required"] else "[dim]No[/dim]"
            
            table.add_row(
                tool_name,
                status,
                required,
                info["description"]
            )
        
        console.print(table)
    
    # Print warnings
    if required_missing:
        console.print("\n[bold red]⚠️  REQUIRED TOOLS MISSING:[/bold red]")
        for tool in required_missing:
            console.print(f"  - [red]{tool}[/red]")
        console.print("\n[yellow]Project will NOT work without these tools![/yellow]")
    
    if optional_missing:
        console.print("\n[bold yellow]ℹ️  Optional tools missing:[/bold yellow]")
        for tool in optional_missing:
            console.print(f"  - [dim]{tool}[/dim]")
        console.print("\n[dim]Project will work but some features will be disabled.[/dim]")
    
    # Print installation commands
    if show_fix and (required_missing or optional_missing):
        console.print("\n[bold cyan]━━━ Installation Commands ━━━[/bold cyan]\n")
        
        if required_missing:
            console.print("[bold red]Required tools:[/bold red]")
            for category, tools in results.items():
                for tool_name, info in tools.items():
                    if not info["installed"] and info["required"]:
                        console.print(f"\n# {tool_name}")
                        console.print(f"[green]{info['install']}[/green]")
        
        if optional_missing:
            console.print("\n[bold yellow]Optional tools:[/bold yellow]")
            for category, tools in results.items():
                for tool_name, info in tools.items():
                    if not info["installed"] and not info["required"]:
                        console.print(f"\n# {tool_name}")
                        console.print(f"[dim]{info['install']}[/dim]")
    
    # Final verdict
    console.print("\n")
    if not required_missing:
        console.print("[bold green]✓ All required tools are installed! You're ready to go.[/bold green]")
        return 0
    else:
        console.print("[bold red]✗ Some required tools are missing. Install them first.[/bold red]")
        console.print("[dim]Run with --fix to see installation commands.[/dim]")
        return 1


# =============================================================================
# Main
# =============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Check if all required tools are installed"
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Show installation commands for missing tools"
    )
    
    args = parser.parse_args()
    
    console.print("[bold cyan]Checking tool dependencies...[/bold cyan]")
    results = check_all_tools()
    exit_code = print_results(results, show_fix=args.fix)
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
