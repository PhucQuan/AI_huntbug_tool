import time
import logging
import asyncio
import httpx
from rich.console import Console

console = Console()
logger = logging.getLogger("recon_auto.safeguards")

class ScopeResult:
    def __init__(self, allowed: bool, reason: str):
        self.allowed = allowed
        self.reason = reason

class StressLevel:
    def __init__(self, is_stressed: bool, suggested_rate_limit: float):
        self.is_stressed = is_stressed
        self.suggested_rate_limit = suggested_rate_limit

class EthicalSafeguards:
    """Ensures scanning targets are in scope and not experiencing DoS."""

    def __init__(self, default_rate_limit: float = 2.0):
        self.default_rate_limit = default_rate_limit

    def check_scope(self, url: str, scope: list[str], out_of_scope: list[str]) -> ScopeResult:
        """
        Validates whether a given URL is permitted for scanning.
        """
        for oos in out_of_scope:
            if oos in url:
                return ScopeResult(False, f"URL matches out-of-scope rule: {oos}")
        
        in_scope = False
        for s in scope:
            if s in url:
                in_scope = True
                break
                
        if not in_scope:
            return ScopeResult(False, "URL does not match any in-scope rules")
            
        return ScopeResult(True, "In scope")

    async def detect_stress(self, target_url: str) -> StressLevel:
        """
        Monitors target response times and status codes to detect stress.
        """
        try:
            async with httpx.AsyncClient() as client:
                start_time = time.time()
                resp = await client.get(target_url, timeout=5.0)
                dur = time.time() - start_time
                
                # Check for rate limiting codes (429, 503)
                if resp.status_code in [429, 503, 502, 504]:
                    console.print(f"[!] Stress detected on {target_url} (HTTP {resp.status_code})")
                    return StressLevel(True, 0.5) # throttle heavily
                
                # Check for abnormal latency > 3 seconds
                if dur > 3.0:
                    console.print(f"[!] High latency detected on {target_url} ({dur:.2f}s)")
                    return StressLevel(True, 1.0) # throttle moderately
                    
                return StressLevel(False, self.default_rate_limit)
        except Exception as e:
            logger.warning(f"Failed to check stress level for {target_url}: {e}")
            return StressLevel(False, self.default_rate_limit)

    async def rate_limiter(self, current_rate: float):
        """Enforces a sleep based on the current requests_per_second limit."""
        if current_rate <= 0:
            current_rate = 0.1
        delay = 1.0 / current_rate
        await asyncio.sleep(delay)
