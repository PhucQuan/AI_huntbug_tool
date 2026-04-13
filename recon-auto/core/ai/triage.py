import os
import re
import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

from rich.console import Console

console = Console()


def _init_gemini_client(api_key: str):
    """Khởi tạo Gemini client, trả về None nếu không có package."""
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        return client
    except ImportError:
        console.print("[!] google-genai not installed. Run: pip install google-genai")
        return None
    except Exception as e:
        console.print(f"[!] Gemini init error: {e}")
        return None

@dataclass
class VerificationResult:
    finding_id: int
    is_confirmed: bool          # True = real bug, False = FP
    confidence: float           # 0.0-1.0
    reason: str                 # Reason for FP or IP
    verified_by: str            # "rule_based" or "ai"
    needs_manual_check: bool    # True if uncertain

@dataclass  
class AttackChain:
    name: str
    steps: List[str]
    combined_severity: str
    individual_severities: List[str]
    effort: str
    finding_ids: List[int]
    why_higher: str

FP_PATTERNS = {
    "xss": [
        lambda r: "content-security-policy" in r.get("headers", {}),
        lambda r: "&lt;script&gt;" in r.get("body", ""),
        lambda r: r.get("content_type", "").startswith("application/json"),
    ],
    "sqli": [
        lambda r: r.get("response_time", 0) < 4000,
        lambda r: "error" not in r.get("body", "").lower(),
    ],
    "ssrf": [
        lambda r: not r.get("oob_callback", False),
    ],
}

class AITriage:
    """
    Integrates LLM (Gemini API) to analyze scan results, score based on 
    business context, filter false positives, and suggest attack chains.
    """

    def __init__(self, api_key: str = None):
        if not api_key:
            api_key = os.environ.get("GEMINI_API_KEY", "")
        self.client = _init_gemini_client(api_key) if api_key else None

    async def verify_finding(self, finding: Dict[str, Any], finding_id: int) -> VerificationResult:
        """Applies rule-based False Positive filters. Fallback to AI if uncertain."""
        vuln_type = finding.get("vulnerability_type", "").lower()
        response_data = finding.get("response", {})
        
        # 1. Rule-based Fast Check
        if vuln_type in FP_PATTERNS:
            for rule in FP_PATTERNS[vuln_type]:
                try:
                    if rule(response_data):
                        return VerificationResult(
                            finding_id=finding_id, is_confirmed=False, 
                            confidence=0.9, reason="Matched rule-based FP pattern",
                            verified_by="rule_based", needs_manual_check=False
                        )
                except Exception:
                    pass

        # 2. AI Check (Fallback)
        # If we have actual request/response payload:
        if self.client and finding.get("request") and finding.get("response"):
            return await self._ai_verify(finding, finding_id)
            
        return VerificationResult(
            finding_id=finding_id, is_confirmed=True, 
            confidence=0.5, reason="No rules triggered, assuming True Positive",
            verified_by="rule_based", needs_manual_check=True
        )

    async def _ai_verify(self, finding: Dict[str, Any], finding_id: int) -> VerificationResult:
        """Uses Gemini to read raw HTTP payload and judge if it is exploitable."""
        if not self.client:
            return VerificationResult(
                finding_id=finding_id, is_confirmed=True,
                confidence=0.5, reason="No AI client available",
                verified_by="rule_based", needs_manual_check=True
            )
        
        prompt = f"Based on this actual HTTP exchange, is this truly exploitable?\nReq: {finding.get('request')}\nRes: {finding.get('response')}"
        try:
            response = self.client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt
            )
            result_text = response.text.lower()
            is_exploitable = "yes" in result_text or "exploitable" in result_text
            return VerificationResult(
                finding_id=finding_id, is_confirmed=is_exploitable,
                confidence=0.8, reason=response.text[:200],
                verified_by="ai", needs_manual_check=False
            )
        except Exception as e:
            console.print(f"[!] AI verification error: {e}")
            return VerificationResult(
                finding_id=finding_id, is_confirmed=True,
                confidence=0.5, reason="AI error, assuming TP",
                verified_by="rule_based", needs_manual_check=True
            )

    async def contextual_score(self, finding: Dict[str, Any], target_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Uses Gemini to contextualize the severity of the vulnerability based on business.
        """
        if not self.client: 
            finding['severity_adjusted'] = False
            finding['severity'] = finding.get('severity_original', 'low')
            return finding

        system_prompt = """You are a senior bug bounty triager at HackerOne with 10 years experience.
You understand that the same vulnerability has different real-world impact depending on business context.

Scoring rules:
- SSRF on fintech with internal AWS metadata access = Critical
- SSRF on personal blog with no internal network = Low  
- XSS on banking portal = High (can steal 2FA tokens)
- XSS on static marketing site = Low (no sensitive actions)
- SQLi on healthcare = Critical (HIPAA violation risk)
- Rate limit bypass on free tier = Informational

Always justify your severity with business impact, not just technical impact."""
        
        user_prompt = f"""Finding: {finding.get('name')} at {finding.get('url')}
Description: {finding.get('description')}

Target Context: {json.dumps(target_context, indent=2)}

Tasks:
1. Assign severity: critical/high/medium/low/informational
2. Estimate bounty range based on program's payout history
3. Justify severity with business impact (2-3 sentences)
4. Rate exploitability: easy/medium/hard

Return pure JSON with keys: severity, severity_original, severity_adjusted (bool), bounty_estimate, business_impact, exploitability, confidence (float)."""

        try:
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            response = self.client.models.generate_content(
                model="gemini-2.0-flash",
                contents=full_prompt
            )
            result_text = response.text.strip()
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0].strip()
            ai_result = json.loads(result_text)
            finding_copy = finding.copy()
            finding_copy.update(ai_result)
            finding_copy['severity_original'] = finding.get('severity')
            return finding_copy
            
        except Exception as e:
            console.print(f"[!] AI Triage error: {e}")
            finding_copy = finding.copy()
            finding_copy.update({
                "severity_original": finding.get('severity'),
                "severity_adjusted": False,
                "business_impact": "AI analysis failed",
                "bounty_estimate": "N/A",
                "exploitability": "unknown",
                "confidence": 0.0
            })
            return finding_copy

    async def suggest_attack_chains(self, findings: List[Dict[str, Any]], tech_stack: List[str]) -> List[AttackChain]:
        """
        Feeds multiple findings to Gemini to identify chained exploitation paths.
        """
        if not self.client or len(findings) < 2: return []
        
        prompt = f"""You are an offensive security expert. Given these individual findings
and the target's tech stack, suggest possible attack chains that combine
multiple vulnerabilities for greater impact.

Findings: {json.dumps(findings, indent=2)}
Tech Stack: {tech_stack}

Return JSON object with a 'chains' list. Each chain should have:
- name: string
- steps: list of strings
- combined_severity: string
- individual_severities: list of strings
- effort: string
- finding_ids: list of integers
- why_higher: string explaining why chained impact is higher"""

        try:
            response = self.client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt
            )
            result_text = response.text.strip()
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0].strip()
            data = json.loads(result_text)
            chains = []
            for c in data.get('chains', []):
                chains.append(AttackChain(
                    name=c.get('name', 'Unknown Chain'),
                    steps=c.get('steps', []),
                    combined_severity=c.get('combined_severity', 'medium'),
                    individual_severities=c.get('individual_severities', []),
                    effort=c.get('effort', 'medium'),
                    finding_ids=c.get('finding_ids', []),
                    why_higher=c.get('why_higher', '')
                ))
            return chains
        except Exception as e:
            console.print(f"[!] Attack chain suggestion error: {e}")
            return []

    async def triage_findings(self, findings: List[Dict[str, Any]], target_context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Main pipeline to verify, context-score, and suggest chains.
        """
        if not target_context:
            target_context = {}
            
        enriched = []
        for idx, finding in enumerate(findings):
            # 1. Verification
            vr = await self.verify_finding(finding, idx)
            finding['verification'] = asdict(vr)
            
            # If confirmed or needs manual, we contextualize
            if vr.is_confirmed or vr.needs_manual_check:
                scored = await self.contextual_score(finding, target_context)
                enriched.append(scored)
            else:
                finding['severity'] = 'informational'
                finding['business_impact'] = "False Positive: " + vr.reason
                enriched.append(finding)
                
        # Optional: suggest chains in memory or output to console
        return enriched
