"""
core/scan/port_scanner.py — Network Port Scanning
==================================================
Port scanning với:
  - naabu — fast port scanner
  - nmap — detailed service detection
"""

import asyncio
import json
import os
import shutil
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List, Dict

from rich.console import Console

console = Console()


@dataclass
class PortResult:
    host: str
    port: int
    protocol: str
    service: str
    version: str
    state: str


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


async def _run_cmd(cmd: str, timeout: int = 600) -> tuple[str, str]:
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
# naabu — Fast Port Scanner
# =============================================================================

async def run_naabu(
    hosts: List[str],
    ports: str = "1-65535",
    top_ports: int = None,
    rate: int = 1000,
    nmap_integration: bool = False,
) -> List[PortResult]:
    """
    Chạy naabu để scan ports nhanh.
    Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    """
    if not _tool_available("naabu"):
        console.print("[yellow][!] naabu not installed — skipping[/yellow]")
        return []
    
    # Ghi hosts vào temp file
    tmp_hosts = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp_hosts.write("\n".join(hosts))
    tmp_hosts.close()
    
    tmp_output = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp_output.close()
    
    try:
        cmd_parts = [
            f"naabu -list {tmp_hosts.name}",
            f"-rate {rate}",
            "-json",
            f"-o {tmp_output.name}",
            "-silent",
        ]
        
        if top_ports:
            cmd_parts.append(f"-top-ports {top_ports}")
        else:
            cmd_parts.append(f"-p {ports}")
        
        if nmap_integration:
            cmd_parts.append("-nmap-cli 'nmap -sV -sC'")
        
        cmd = " ".join(cmd_parts)
        console.print(f"[cyan][→] Running naabu on {len(hosts)} hosts...[/cyan]")
        
        await _run_cmd(cmd, timeout=600)
        
        # Parse JSON output
        results = []
        if os.path.exists(tmp_output.name):
            with open(tmp_output.name) as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        results.append(PortResult(
                            host=data.get("host", ""),
                            port=data.get("port", 0),
                            protocol=data.get("protocol", "tcp"),
                            service="",
                            version="",
                            state="open",
                        ))
                    except json.JSONDecodeError:
                        continue
        
        console.print(f"[green][✓] naabu: {len(results)} open ports found[/green]")
        return results
        
    finally:
        os.unlink(tmp_hosts.name)
        if os.path.exists(tmp_output.name):
            os.unlink(tmp_output.name)


# =============================================================================
# nmap — Detailed Service Detection
# =============================================================================

async def run_nmap(
    host: str,
    ports: str = None,
    scan_type: str = "sV",  # sV=version, sC=scripts, A=aggressive
    timeout_mins: int = 10,
) -> List[PortResult]:
    """
    Chạy nmap để detect services chi tiết.
    """
    if not _tool_available("nmap"):
        console.print("[yellow][!] nmap not installed — skipping[/yellow]")
        return []
    
    tmp_output = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
    tmp_output.close()
    
    try:
        cmd_parts = [
            f"nmap -{scan_type}",
            f"-oX {tmp_output.name}",
        ]
        
        if ports:
            cmd_parts.append(f"-p {ports}")
        else:
            cmd_parts.append("-p-")  # All ports
        
        cmd_parts.append(host)
        cmd = " ".join(cmd_parts)
        
        console.print(f"[cyan][→] Running nmap on {host}...[/cyan]")
        await _run_cmd(cmd, timeout=timeout_mins * 60)
        
        # Parse XML output
        results = []
        if os.path.exists(tmp_output.name):
            tree = ET.parse(tmp_output.name)
            root = tree.getroot()
            
            for host_elem in root.findall("host"):
                host_addr = host_elem.find("address").get("addr")
                
                for port_elem in host_elem.findall(".//port"):
                    port_num = int(port_elem.get("portid"))
                    protocol = port_elem.get("protocol")
                    
                    state_elem = port_elem.find("state")
                    state = state_elem.get("state") if state_elem is not None else "unknown"
                    
                    service_elem = port_elem.find("service")
                    service = service_elem.get("name", "") if service_elem is not None else ""
                    version = service_elem.get("version", "") if service_elem is not None else ""
                    
                    results.append(PortResult(
                        host=host_addr,
                        port=port_num,
                        protocol=protocol,
                        service=service,
                        version=version,
                        state=state,
                    ))
        
        console.print(f"[green][✓] nmap: {len(results)} ports scanned on {host}[/green]")
        return results
        
    finally:
        if os.path.exists(tmp_output.name):
            os.unlink(tmp_output.name)


# =============================================================================
# masscan — Ultra-fast scanner (optional)
# =============================================================================

async def run_masscan(
    hosts: List[str],
    ports: str = "0-65535",
    rate: int = 10000,
) -> List[PortResult]:
    """
    Chạy masscan — cực nhanh nhưng ít chi tiết.
    """
    if not _tool_available("masscan"):
        console.print("[yellow][!] masscan not installed — skipping[/yellow]")
        return []
    
    tmp_hosts = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp_hosts.write("\n".join(hosts))
    tmp_hosts.close()
    
    tmp_output = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp_output.close()
    
    try:
        cmd = f"masscan -iL {tmp_hosts.name} -p{ports} --rate {rate} -oJ {tmp_output.name}"
        console.print(f"[cyan][→] Running masscan on {len(hosts)} hosts...[/cyan]")
        
        await _run_cmd(cmd, timeout=300)
        
        results = []
        if os.path.exists(tmp_output.name):
            with open(tmp_output.name) as f:
                try:
                    data = json.load(f)
                    for item in data:
                        if "ports" in item:
                            for port_info in item["ports"]:
                                results.append(PortResult(
                                    host=item.get("ip", ""),
                                    port=port_info.get("port", 0),
                                    protocol=port_info.get("proto", "tcp"),
                                    service="",
                                    version="",
                                    state="open",
                                ))
                except json.JSONDecodeError:
                    pass
        
        console.print(f"[green][✓] masscan: {len(results)} open ports found[/green]")
        return results
        
    finally:
        os.unlink(tmp_hosts.name)
        if os.path.exists(tmp_output.name):
            os.unlink(tmp_output.name)


# =============================================================================
# Orchestrator
# =============================================================================

async def run_port_scan_pipeline(
    hosts: List[str],
    fast_scan: bool = True,
    detailed_scan: bool = False,
    top_ports: int = 1000,
) -> Dict[str, List[PortResult]]:
    """
    Chạy port scanning pipeline.
    
    fast_scan: dùng naabu hoặc masscan
    detailed_scan: dùng nmap cho service detection
    """
    console.print(f"[cyan][→] Starting port scan on {len(hosts)} hosts...[/cyan]")
    
    results = {
        "naabu": [],
        "nmap": [],
        "masscan": [],
    }
    
    # Fast scan
    if fast_scan:
        if _tool_available("naabu"):
            results["naabu"] = await run_naabu(hosts, top_ports=top_ports)
        elif _tool_available("masscan"):
            results["masscan"] = await run_masscan(hosts, ports="1-1000")
    
    # Detailed scan (chỉ scan host đầu tiên để demo)
    if detailed_scan and hosts:
        if _tool_available("nmap"):
            # Lấy ports từ fast scan để nmap scan chi tiết
            open_ports = set()
            for port_result in results["naabu"] + results["masscan"]:
                if port_result.host == hosts[0]:
                    open_ports.add(str(port_result.port))
            
            if open_ports:
                ports_str = ",".join(sorted(open_ports, key=int)[:50])  # Limit 50 ports
                results["nmap"] = await run_nmap(hosts[0], ports=ports_str)
    
    total_ports = sum(len(v) for v in results.values())
    console.print(f"\n[bold green][★] Port Scan Summary: {total_ports} open ports found[/bold green]")
    
    return results
