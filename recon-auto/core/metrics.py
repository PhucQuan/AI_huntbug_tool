from datetime import datetime
import json
from dataclasses import dataclass, field
from typing import Dict, List
from rich.console import Console

console = Console()

@dataclass
class ScanMetrics:
    """Tracks performance and efficacy metrics of each scan."""
    
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime = None
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rate_limited_count: int = 0
    findings_count: Dict[str, int] = field(default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0})
    false_positives: int = 0
    tools_used: List[str] = field(default_factory=list)
    
    def finish_scan(self):
        self.end_time = datetime.now()

    def duration_seconds(self) -> float:
        if not self.end_time:
            return (datetime.now() - self.start_time).total_seconds()
        return (self.end_time - self.start_time).total_seconds()

    def false_positive_rate(self) -> float:
        """false_positives / total_findings"""
        total = sum(self.findings_count.values()) + self.false_positives
        if total == 0:
            return 0.0
        return (self.false_positives / total) * 100.0

    def requests_per_minute(self) -> float:
        """Throughput metric"""
        dur_mins = self.duration_seconds() / 60.0
        if dur_mins <= 0:
            return 0.0
        return self.total_requests / dur_mins

    def print_summary(self):
        dur = self.duration_seconds()
        m, s = divmod(int(dur), 60)
        dur_str = f"{m}m {s}s"
        
        console.print("\n  ──────────── Scan Metrics ────────────")
        console.print(f"  Duration        : {dur_str}")
        console.print(f"  Total requests  : {self.total_requests}")
        console.print(f"  Req/minute      : {self.requests_per_minute():.0f}")
        
        findings_str = ", ".join([f"{count} {sev.capitalize()}" for sev, count in self.findings_count.items() if count > 0])
        total_finds = sum(self.findings_count.values())
        console.print(f"  Findings        : {total_finds} ({findings_str})")
        
        console.print(f"  False positives : {self.false_positives} (filtered by AI)")
        console.print(f"  FP rate         : {self.false_positive_rate():.1f}%")
        console.print(f"  Tools used      : {', '.join(self.tools_used)}")
        console.print("  ──────────────────────────────────────\n")

    def to_json(self) -> str:
        """Exports metrics for tracking over time."""
        data = {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds(),
            "total_requests": self.total_requests,
            "requests_per_minute": self.requests_per_minute(),
            "findings": self.findings_count,
            "false_positives": self.false_positives,
            "false_positive_rate": self.false_positive_rate(),
            "tools": self.tools_used
        }
        return json.dumps(data, indent=4)
