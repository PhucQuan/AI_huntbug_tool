import asyncio
import json
import logging
import os
from typing import List, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from rich.console import Console

console = Console()
logger = logging.getLogger("recon_auto.nuclei")

@dataclass
class Finding:
    url: str
    template_id: str
    name: str
    severity: str
    description: str
    matched_at: str
    timestamp: str

class NucleiRunner:
    """
    Handles running Nuclei scans against discovered alive hosts.
    Avoids noise by scanning in distinct phases based on technology scope.
    """
    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.findings: List[Finding] = []

    async def _run_command(self, cmd: str) -> List[Dict[str, Any]]:
        """Executes nuclei command and parses line-by-line JSON output."""
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            results = []
            for line in stdout.decode().splitlines():
                if not line.strip(): continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return results
        except Exception as e:
            logger.error(f"Nuclei execution error: {e}")
            return []

    async def run_nuclei_phase(self, urls: List[str], templates: List[str], 
                               severity: str = "medium,high,critical", rate_limit: int = 15) -> List[Dict[str, Any]]:
        if not urls: return []
        
        target_file = f"{self.output_dir}/nuclei_targets.txt"
        with open(target_file, "w") as f:
            f.write("\n".join(urls))

        template_flags = " ".join([f"-t {t}" for t in templates])
        cmd = (f"nuclei -l {target_file} {template_flags} -s {severity} "
               f"-json -rate-limit {rate_limit} -timeout 10 -silent")
               
        console.print(f"[→] Running nuclei phase...")
        return await self._run_command(cmd)

    async def run_full_nuclei_pipeline(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Orchestrates Nuclei into 3 Smart Phases based on context.
        """
        urls = [h['url'] for h in hosts]
        all_raw_results = []
        
        # PHASE 1: Safe templates (always run)
        console.print("[→] Running nuclei PHASE 1 (safe templates)...")
        phase1_templates = ["exposures/", "misconfiguration/", "technologies/"]
        res1 = await self.run_nuclei_phase(urls, phase1_templates, severity="info,low,medium,high,critical")
        all_raw_results.extend(res1)
        
        # PHASE 2: Medium/High risk vulnerabilities (Run cautiously, typically requiring scope checks)
        console.print("[→] Running nuclei PHASE 2 (vulnerabilities, cves)...")
        phase2_templates = ["vulnerabilities/", "cves/"]
        res2 = await self.run_nuclei_phase(urls, phase2_templates)
        all_raw_results.extend(res2)
        
        # PHASE 3: Technology-specific (Based on web analysis tech detection)
        # We group hosts by technology to only run relevant WP/Laravel/etc. templates
        tech_map = {}
        for h in hosts:
            for tech in h.get('technologies', []):
                t = tech.lower()
                if t not in tech_map: tech_map[t] = []
                tech_map[t].append(h['url'])
                
        for tech, tech_urls in tech_map.items():
            if "wordpress" in tech:
                console.print(f"[→] Running nuclei PHASE 3 (WordPress specific) on {len(tech_urls)} hosts...")
                res3 = await self.run_nuclei_phase(tech_urls, ["cms/wordpress/"])
                all_raw_results.extend(res3)
                
            # Extend more conditions like laravel, jira, etc.

        # Process Results
        parsed_findings = await self.parse_results(all_raw_results)
        self.save_findings(parsed_findings)
        
        return [asdict(f) for f in parsed_findings]

    async def parse_results(self, raw_outputs: List[Dict[str, Any]]) -> List[Finding]:
        """Parses the JSON output dictionaries from nuclei into structured Finding models."""
        parsed = []
        for issue in raw_outputs:
            finding = Finding(
                url=issue.get('host', ''),
                template_id=issue.get('template-id', ''),
                name=issue.get('info', {}).get('name', 'Unknown Vulnerability'),
                severity=issue.get('info', {}).get('severity', 'low').lower(),
                description=issue.get('info', {}).get('description', ''),
                matched_at=issue.get('matched-at', ''),
                timestamp=issue.get('timestamp', datetime.now().isoformat())
            )
            parsed.append(finding)
        return parsed

    def save_findings(self, findings: List[Finding]) -> None:
        """Deduplicates and saves to memory (database integration done at KnowledgeGraph side)."""
        seen = set()
        for f in findings:
            key = f"{f.url}-{f.template_id}"
            if key not in seen:
                self.findings.append(f)
                seen.add(key)
        
        # Optional file dump
        with open(f"{self.output_dir}/findings_{datetime.now().strftime('%Y%m%d')}.json", "w") as f:
            json.dump([asdict(fd) for fd in self.findings], f, indent=4)
