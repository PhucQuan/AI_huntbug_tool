from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# --- Data Models ---

class Subdomain(BaseModel):
    """Stores discovered subdomains."""
    id: Optional[int] = None
    domain: str
    target_domain: str  # The root domain from targets.yaml
    source: str         # e.g., 'subfinder', 'amass'
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

class AliveHost(BaseModel):
    """Stores hosts that responded to HTTP/HTTPS checks."""
    id: Optional[int] = None
    subdomain: str
    ip_address: Optional[str] = None
    status_code: int
    title: Optional[str] = None
    tech_stack: List[str] = []
    content_length: int
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

class ScanResult(BaseModel):
    """Stores raw output from specific tools (e.g., nuclei, nmap)."""
    id: Optional[int] = None
    host: str
    tool_name: str
    raw_output: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class Finding(BaseModel):
    """Stores validated vulnerabilities/interesting findings."""
    id: Optional[int] = None
    host: str
    severity: str  # Critical, High, Medium, Low, Info
    description: str
    tool_name: str
    remediation: Optional[str] = None
    ai_triage_notes: Optional[str] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


# --- Database Manager Skeleton ---

class DatabaseManager:
    """Handles all SQLite interactions using aiosqlite."""

    def __init__(self, db_path: str = "recon_auto.db"):
        self.db_path = db_path

    async def initialize_db(self):
        """
        Creates the necessary tables if they don't exist.
        Tables to create: subdomains, alive_hosts, scan_results, findings.
        """
        pass

    async def add_subdomain(self, subdomain: Subdomain):
        """Inserts a new subdomain into the database."""
        pass

    async def add_alive_host(self, host: AliveHost):
        """Inserts an alive host into the database."""
        pass

    async def add_scan_result(self, result: ScanResult):
        """Inserts a tool's raw output."""
        pass

    async def add_finding(self, finding: Finding):
        """Inserts a verified finding."""
        pass

    async def get_all_subdomains(self, domain: str) -> List[Subdomain]:
        """Retrieves all subdomains for a given target domain."""
        pass

    async def get_all_findings(self) -> List[Finding]:
        """Retrieves all findings across all targets."""
        pass
