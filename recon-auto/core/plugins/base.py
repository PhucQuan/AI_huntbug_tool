from abc import ABC, abstractmethod
from dataclasses import dataclass
import shutil

@dataclass
class Target:
    domain: str
    urls: list[str]
    tech_stack: list[str]
    scope: list[str]

@dataclass  
class Finding:
    url: str
    vulnerability_type: str
    severity: str
    description: str
    request: str = ""
    response: str = ""
    payload: str = ""

class BasePlugin(ABC):
    name: str           # unique identifier
    description: str    # short description
    stage: str          # "recon" / "scan" / "exploit"
    author: str = "unknown"
    version: str = "1.0.0"
    requires: list[str] = []   # System dependencies (like sqlmap, nmap)
    
    @abstractmethod
    async def run(self, target: Target) -> list[Finding]:
        """Core logic of the plugin to be implemented."""
        pass
    
    async def check_dependencies(self) -> bool:
        """Verifies if the required system dependencies are installed."""
        for req in self.requires:
            if shutil.which(req) is None:
                return False
        return True
    
    def is_in_scope(self, url: str, scope: list[str]) -> bool:
        """Helper to check if the URL falls within the defined scope rules."""
        if not scope: return True
        return any(s in url for s in scope)
