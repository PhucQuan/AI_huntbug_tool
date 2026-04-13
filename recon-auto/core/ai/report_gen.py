"""
core/ai/report_gen.py — AI-Powered HackerOne Report Generator
==============================================================
Tự động tạo:
  • Draft báo cáo chuẩn HackerOne format (Markdown)
  • CVSS 3.1 vector + score tính theo logic rule-based
  • Export PDF (nếu weasyprint/reportlab được cài)

Dùng Jinja2 cho template → dễ thay thế template cho Bugcrowd/Intigriti.
"""

import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Template
from rich.console import Console

console = Console()

# =============================================================================
# Data Models
# =============================================================================

@dataclass
class CVSSVector:
    """CVSS 3.1 base metrics."""
    attack_vector: str          = "N"   # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str      = "L"   # L=Low, H=High
    privileges_required: str    = "N"   # N=None, L=Low, H=High
    user_interaction: str       = "N"   # N=None, R=Required
    scope: str                  = "U"   # U=Unchanged, C=Changed
    confidentiality: str        = "H"   # N=None, L=Low, H=High
    integrity: str              = "H"
    availability: str           = "N"

    def vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
            f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
            f"/S:{self.scope}/C:{self.confidentiality}"
            f"/I:{self.integrity}/A:{self.availability}"
        )

    def approximate_score(self) -> float:
        """
        Rough score estimator (not the official algorithm, but good enough for draft reports).
        """
        severity_map = {
            "critical": 9.5, "high": 7.5, "medium": 5.0,
            "low": 3.0, "informational": 0.0,
        }
        # TODO: replace with proper CVSS lib (cvss3 package)
        return severity_map.get("high", 5.0)


@dataclass
class ReportDraft:
    title: str
    severity: str
    cvss_vector: CVSSVector
    cvss_score: float
    target_url: str
    vulnerability_type: str
    summary: str
    steps_to_reproduce: list[str]
    impact: str
    remediation: str
    bounty_estimate: str
    generated_at: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# =============================================================================
# CVSS Calculator (Rule-Based)
# =============================================================================

VULN_CVSS_PRESETS = {
    "xss": CVSSVector(attack_vector="N", attack_complexity="L", privileges_required="N",
                      user_interaction="R", scope="C", confidentiality="L",
                      integrity="L", availability="N"),
    "sqli": CVSSVector(attack_vector="N", attack_complexity="L", privileges_required="N",
                       user_interaction="N", scope="U", confidentiality="H",
                       integrity="H", availability="H"),
    "ssrf": CVSSVector(attack_vector="N", attack_complexity="L", privileges_required="L",
                       user_interaction="N", scope="C", confidentiality="H",
                       integrity="L", availability="N"),
    "lfi": CVSSVector(attack_vector="N", attack_complexity="L", privileges_required="N",
                      user_interaction="N", scope="U", confidentiality="H",
                      integrity="N", availability="N"),
    "rce": CVSSVector(attack_vector="N", attack_complexity="L", privileges_required="N",
                      user_interaction="N", scope="C", confidentiality="H",
                      integrity="H", availability="H"),
    "idor": CVSSVector(attack_vector="N", attack_complexity="L", privileges_required="L",
                       user_interaction="N", scope="U", confidentiality="H",
                       integrity="L", availability="N"),
    "default": CVSSVector(),
}

SEVERITY_SCORES = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "informational": 0.0,
}


def calculate_cvss(finding: dict) -> tuple[CVSSVector, float]:
    """Pick best CVSS preset for the vuln type, return (vector, score)."""
    vuln_type = finding.get("vulnerability_type", "default").lower()
    vector = VULN_CVSS_PRESETS.get(vuln_type, VULN_CVSS_PRESETS["default"])
    severity = finding.get("severity", "medium").lower()
    score = SEVERITY_SCORES.get(severity, 5.0)
    return vector, score


# =============================================================================
# Jinja2 Markdown Template
# =============================================================================

HACKERONE_MARKDOWN_TEMPLATE = """\
# {{ report.title }}

**Severity:** {{ report.severity | upper }}  
**CVSS Score:** {{ report.cvss_score }} ({{ report.cvss_vector.vector_string() }})  
**Target:** {{ report.target_url }}  
**Type:** {{ report.vulnerability_type | upper }}  
**Bounty Estimate:** {{ report.bounty_estimate }}  

---

## Summary

{{ report.summary }}

---

## Steps to Reproduce

{% for step in report.steps_to_reproduce %}
{{ loop.index }}. {{ step }}
{% endfor %}

---

## Impact

{{ report.impact }}

---

## Remediation

{{ report.remediation }}

---

## CVSS Vector

```
{{ report.cvss_vector.vector_string() }}
```

*Report generated by recon-auto on {{ report.generated_at }}*
"""


# =============================================================================
# Main Generator Class
# =============================================================================

class ReportGenerator:
    """
    Generates HackerOne-format bug reports using:
    1. Rule-based CVSS calculation
    2. Gemini API for narrative prose (summary, impact, remediation)
    3. Jinja2 template for Markdown export
    """

    def __init__(self, api_key: str = None, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.client = None
        if not api_key:
            api_key = os.environ.get("GEMINI_API_KEY", "")
        if api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=api_key)
                self.client = genai.GenerativeModel("gemini-1.5-flash")
            except ImportError:
                console.print("[!] google-generativeai not installed. Using template-only report generation.")

    # ── Public API ────────────────────────────────────────────────────────

    async def generate_report(
        self,
        finding: dict,
        target_context: dict | None = None,
        preview: bool = False,
    ) -> ReportDraft:
        """
        Tạo ReportDraft từ một finding dict.
        finding keys: url, vulnerability_type, severity, name, description,
                      request, response, ai_business_impact, ai_bounty_estimate
        """
        target_context = target_context or {}
        cvss_vector, cvss_score = calculate_cvss(finding)

        # Generate narrative with AI (or fallback to template)
        narrative = await self._generate_narrative(finding, target_context)

        report = ReportDraft(
            title=self._build_title(finding),
            severity=finding.get("severity", "medium"),
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            target_url=finding.get("url", "N/A"),
            vulnerability_type=finding.get("vulnerability_type", "Unknown"),
            summary=narrative["summary"],
            steps_to_reproduce=narrative["steps"],
            impact=narrative["impact"],
            remediation=narrative["remediation"],
            bounty_estimate=finding.get("ai_bounty_estimate", "N/A"),
        )

        if preview:
            self._print_preview(report)
        return report

    def export_markdown(self, report: ReportDraft, filename: str | None = None) -> Path:
        """Render report to Markdown file."""
        template = Template(HACKERONE_MARKDOWN_TEMPLATE)
        content = template.render(report=report)

        if not filename:
            slug = report.title.lower().replace(" ", "_")[:40]
            filename = f"{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

        out_path = self.output_dir / filename
        out_path.write_text(content, encoding="utf-8")
        console.print(f"[green][✓] Report exported:[/green] {out_path}")
        return out_path

    def export_pdf(self, report: ReportDraft, filename: str | None = None) -> Path | None:
        """Render report to PDF (requires weasyprint)."""
        try:
            from weasyprint import HTML as WPHtml

            md_path = self.export_markdown(report)
            html_content = self._md_to_html(md_path.read_text())

            if not filename:
                filename = md_path.stem + ".pdf"

            pdf_path = self.output_dir / filename
            WPHtml(string=html_content).write_pdf(str(pdf_path))
            console.print(f"[green][✓] PDF exported:[/green] {pdf_path}")
            return pdf_path
        except ImportError:
            console.print("[!] weasyprint not installed. Run: pip install weasyprint")
            return None
        except Exception as e:
            console.print(f"[!] PDF export failed: {e}")
            return None

    # ── Private Helpers ───────────────────────────────────────────────────

    async def _generate_narrative(self, finding: dict, target_context: dict) -> dict:
        """Use Claude to write report narrative, or return template fallback."""
        if self.client:
            return await self._ai_narrative(finding, target_context)
        return self._template_narrative(finding)

    async def _ai_narrative(self, finding: dict, target_context: dict) -> dict:
        """Call Gemini API to generate rich narrative prose."""
        prompt = f"""You are a senior bug bounty hunter writing a professional vulnerability report for HackerOne.

Finding:
- Name: {finding.get('name')}
- Type: {finding.get('vulnerability_type')}
- Severity: {finding.get('severity')}
- URL: {finding.get('url')}
- Description: {finding.get('description')}
- AI Impact: {finding.get('ai_business_impact', 'N/A')}

Target context: {json.dumps(target_context, indent=2)}

Write a professional bug report. Return ONLY valid JSON with these exact keys:
{{
  "summary": "2-3 sentence executive summary",
  "steps": ["Step 1", "Step 2", "Step 3 — include actual request/response examples"],
  "impact": "Business impact paragraph (2-3 sentences, specific to this company type)",
  "remediation": "Specific, actionable fix recommendations (2-3 sentences)"
}}"""
        
        try:
            response = self.client.generate_content(prompt)
            result_text = response.text.strip()
            
            # Extract JSON from markdown code blocks if present
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0].strip()
            
            return json.loads(result_text)
        except Exception as e:
            console.print(f"[!] AI narrative generation failed: {e}. Using template fallback.")
            return self._template_narrative(finding)

    def _template_narrative(self, finding: dict) -> dict:
        """Fallback template-based narrative (no API cost)."""
        vuln = finding.get("vulnerability_type", "vulnerability").upper()
        url = finding.get("url", "TARGET_URL")
        desc = finding.get("description", "No description provided.")

        return {
            "summary": (
                f"A {vuln} vulnerability was identified at `{url}`. {desc}"
            ),
            "steps": [
                f"Navigate to: `{url}`",
                "Send the following request (see below)",
                "Observe the response confirming the vulnerability",
            ],
            "impact": (
                f"This {vuln} vulnerability may allow an attacker to compromise "
                "confidential data or perform unauthorized actions on behalf of users."
            ),
            "remediation": (
                "Validate and sanitize all user-supplied input. "
                "Implement proper output encoding. "
                "Follow OWASP recommendations for this vulnerability class."
            ),
        }

    def _build_title(self, finding: dict) -> str:
        vuln = finding.get("vulnerability_type", "Vulnerability").upper()
        host = finding.get("url", "").split("/")[2] if "//" in finding.get("url", "") else "Target"
        return f"[{vuln}] {host} — {finding.get('name', 'Security Issue')}"

    def _print_preview(self, report: ReportDraft) -> None:
        from rich.markdown import Markdown
        template = Template(HACKERONE_MARKDOWN_TEMPLATE)
        content = template.render(report=report)
        console.print(Markdown(content))

    def _md_to_html(self, md_text: str) -> str:
        """Simple Markdown → HTML wrapper for PDF export."""
        try:
            import markdown
            return f"<html><body>{markdown.markdown(md_text)}</body></html>"
        except ImportError:
            # Ultra-minimal fallback
            return f"<html><body><pre>{md_text}</pre></body></html>"
