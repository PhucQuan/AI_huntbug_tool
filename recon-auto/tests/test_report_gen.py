"""
tests/test_report_gen.py — Unit Tests for Report Generator
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core.ai.report_gen import (
    ReportGenerator,
    calculate_cvss,
    CVSSVector,
    VULN_CVSS_PRESETS,
)


class TestCVSSCalculation:

    def test_sqli_preset_returns_high_score(self):
        finding = {"vulnerability_type": "sqli", "severity": "high"}
        vector, score = calculate_cvss(finding)
        assert score == 7.5
        assert vector.confidentiality == "H"
        assert vector.integrity == "H"

    def test_xss_preset_requires_user_interaction(self):
        finding = {"vulnerability_type": "xss", "severity": "medium"}
        vector, score = calculate_cvss(finding)
        assert vector.user_interaction == "R"   # XSS requires victim to click

    def test_rce_preset_is_scope_changed(self):
        finding = {"vulnerability_type": "rce", "severity": "critical"}
        vector, score = calculate_cvss(finding)
        assert vector.scope == "C"              # RCE crosses trust boundaries
        assert score == 9.5

    def test_unknown_vuln_uses_default(self):
        finding = {"vulnerability_type": "custom_weird_bug", "severity": "low"}
        vector, score = calculate_cvss(finding)
        assert score == 2.5                     # low severity score

    def test_cvss_vector_string_format(self):
        v = CVSSVector(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="U", confidentiality="H", integrity="H", availability="N"
        )
        vs = v.vector_string()
        assert vs.startswith("CVSS:3.1/")
        assert "AV:N" in vs
        assert "C:H" in vs
        assert "I:H" in vs


class TestReportGenerator:

    @pytest.fixture
    def gen(self, tmp_path):
        """Generator without API client (no cost in tests)."""
        g = ReportGenerator(api_key=None, output_dir=str(tmp_path / "reports"))
        g.client = None
        return g

    @pytest.mark.asyncio
    async def test_generate_report_no_ai(self, gen):
        """Falls back to template narrative when no API key."""
        finding = {
            "url": "https://example.com/search?q=test",
            "vulnerability_type": "xss",
            "severity": "high",
            "name": "Reflected XSS in search param",
            "description": "Unsanitized input reflected in response",
        }
        report = await gen.generate_report(finding)

        assert "XSS" in report.title.upper()
        assert report.severity == "high"
        assert len(report.steps_to_reproduce) >= 2
        assert report.cvss_score > 0

    @pytest.mark.asyncio
    async def test_export_markdown_creates_file(self, gen, tmp_path):
        finding = {
            "url": "https://example.com/admin",
            "vulnerability_type": "idor",
            "severity": "high",
            "name": "IDOR on admin endpoint",
            "description": "Direct object reference without auth check",
        }
        report = await gen.generate_report(finding)
        path = gen.export_markdown(report, filename="test_report.md")

        assert path.exists()
        content = path.read_text()
        assert "IDOR" in content.upper()
        assert "CVSS" in content

    @pytest.mark.asyncio
    async def test_report_title_includes_vuln_and_host(self, gen):
        finding = {
            "url": "https://api.target.com/v1/users",
            "vulnerability_type": "sqli",
            "severity": "critical",
            "name": "SQL Injection in users endpoint",
            "description": "Error-based SQLi found",
        }
        report = await gen.generate_report(finding)
        assert "SQLI" in report.title.upper() or "SQL" in report.title.upper()
        assert "api.target.com" in report.title

    @pytest.mark.asyncio
    async def test_ai_narrative_fallback_on_error(self, gen):
        """If AI call raises exception, should fall back to template — no crash."""
        gen.client = MagicMock()
        gen.client.messages.create.side_effect = Exception("API error")

        finding = {
            "url": "https://example.com/upload",
            "vulnerability_type": "lfi",
            "severity": "high",
            "name": "LFI via file parameter",
            "description": "File inclusion via arbitrary path",
        }
        # Should not raise
        report = await gen.generate_report(finding)
        assert report is not None
        assert len(report.summary) > 0
