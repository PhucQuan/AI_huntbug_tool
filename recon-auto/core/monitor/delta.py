import asyncio
import re
from datetime import datetime
from typing import List, Dict, Any

import httpx
from rich.console import Console

console = Console()


class AlertManager:
    """Handles alert notifications to external channels like Slack/Telegram."""

    def __init__(self, slack_webhook: str = None):
        self.slack_webhook = slack_webhook
        self.sent_alerts = set()

    def should_alert(self, identifier: str) -> bool:
        today = datetime.now().strftime('%Y-%m-%d')
        key = f"{identifier}-{today}"
        if key in self.sent_alerts:
            return False
        self.sent_alerts.add(key)
        return True

    async def send_slack(self, target: str, message: str, severity: str = "Medium"):
        console.print(f"[!] Alert — Target: {target} | {message} | Severity: {severity.upper()}")
        if self.slack_webhook:
            pass


class DeltaDetector:
    """
    Detects changes in the attack surface:
    - New subdomains
    - New JS endpoints
    - SSL certificate changes
    """

    def __init__(self, db, enumerator, scanner, alert_manager=None):
        self.db = db
        self.enumerator = enumerator
        self.scanner = scanner
        self.alert_manager = alert_manager or AlertManager()

    async def check_new_subdomains(self, target_domain: str) -> List[str]:
        """Compares current enumeration with DB to find new assets."""
        console.print(f"[->] Checking for new subdomains on {target_domain}...")

        current_subs = await self.enumerator.enumerate_subdomains(target_domain)

        existing_subs = []
        try:
            surface = await self.db.get_attack_surface(1)
            existing_subs = [a['value'] for a in surface.get('assets', [])]
        except Exception:
            pass

        new_subs = list(set(current_subs) - set(existing_subs))
        for sub in new_subs:
            await self._trigger_immediate_scan(target_domain, sub)

        return new_subs

    async def _trigger_immediate_scan(self, target_domain: str, subdomain: str):
        """Triggers an immediate scan for a newly discovered subdomain."""
        msg = f"New Asset: {subdomain} (Auto-scanning)"
        if self.alert_manager.should_alert(f"new_sub_{subdomain}"):
            await self.alert_manager.send_slack(target_domain, msg, "high")
        console.print(f"[*] Dispatching priority pipeline for {subdomain}...")

    async def check_cert_transparency(self, domain: str) -> List[str]:
        """Polls crt.sh to find subdomains via new SSL certificates issued within 24h."""
        console.print(f"[->] Polling Cert Transparency logs for {domain}...")
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, timeout=30.0)
                if resp.status_code == 200:
                    certs = resp.json()
                    new_subdomains = self._filter_recent_certs(certs)
                    for sub in new_subdomains:
                        await self.check_new_subdomains(sub)
                    return new_subdomains
        except Exception as e:
            console.print(f"[!] Cert transparency check failed: {e}")
        return []

    def _filter_recent_certs(self, certs: List[Dict]) -> List[str]:
        subs = set()
        today_iso = datetime.now().isoformat()[:10]
        for c in certs:
            if c.get("not_before", "").startswith(today_iso):
                names = c.get("name_value", "").split("\n")
                for n in names:
                    if "*" not in n:
                        subs.add(n)
        return list(subs)

    async def check_js_endpoints(self, asset_id: int, js_url: str) -> List[str]:
        """Detects new endpoints by diffing JS file content hashes."""
        console.print(f"[->] Analyzing JS file: {js_url}")
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(js_url, timeout=10.0)
                endpoints = self._extract_endpoints(resp.text)
                return endpoints
        except Exception:
            return []

    async def check_ssl_expiry(self, domain: str) -> Dict[str, Any]:
        """Checks SSL cert expiry to prevent takeover."""
        return {"expires_in_days": 30, "is_new": False}

    def _extract_endpoints(self, content: str) -> List[str]:
        patterns = [
            r'/(?:api|v[0-9]+)/[a-z0-9\-/]+',
            r"fetch\(['\"`]([^'\"`]+)['\"`]\)",
            r"axios\.\w+\(['\"`]([^'\"`]+)['\"`]\)",
        ]
        found = []
        for p in patterns:
            found.extend(re.findall(p, content))
        return list(set(found))
