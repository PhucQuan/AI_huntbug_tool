"""
tests/test_safeguards.py — Unit Tests for Ethical Safeguards
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core.safeguards import EthicalSafeguards, ScopeResult, StressLevel


class TestScopeCheck:

    @pytest.fixture
    def sg(self):
        return EthicalSafeguards()

    def test_url_in_scope_passes(self, sg):
        result = sg.check_scope(
            url="https://api.hackerone.com/v1/users",
            scope=["hackerone.com", "api.hackerone.com"],
            out_of_scope=["blog.hackerone.com"],
        )
        assert result.allowed is True

    def test_url_out_of_scope_blocked(self, sg):
        result = sg.check_scope(
            url="https://blog.hackerone.com/post/1",
            scope=["hackerone.com"],
            out_of_scope=["blog.hackerone.com"],
        )
        assert result.allowed is False
        assert "out-of-scope" in result.reason.lower() or "blog.hackerone.com" in result.reason

    def test_url_not_matching_any_scope_blocked(self, sg):
        result = sg.check_scope(
            url="https://completely-different.com/admin",
            scope=["hackerone.com"],
            out_of_scope=[],
        )
        assert result.allowed is False

    def test_exact_domain_match(self, sg):
        result = sg.check_scope(
            url="https://hackerone.com/reports",
            scope=["hackerone.com"],
            out_of_scope=[],
        )
        assert result.allowed is True

    def test_empty_scope_blocks_all(self, sg):
        """Empty scope list = nothing is in scope = should block."""
        result = sg.check_scope(
            url="https://example.com/admin",
            scope=[],
            out_of_scope=[],
        )
        assert result.allowed is False

    def test_out_of_scope_takes_priority(self, sg):
        """Even if URL matches scope, OOS rule takes priority."""
        result = sg.check_scope(
            url="https://oos.example.com/page",
            scope=["*.example.com", "example.com"],
            out_of_scope=["oos.example.com"],
        )
        assert result.allowed is False


class TestStressDetection:

    @pytest.fixture
    def sg(self):
        return EthicalSafeguards(default_rate_limit=2.0)

    @pytest.mark.asyncio
    async def test_normal_response_no_stress(self, sg):
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await sg.detect_stress("https://example.com")

        assert result.is_stressed is False
        assert result.suggested_rate_limit == 2.0

    @pytest.mark.asyncio
    async def test_rate_limit_response_triggers_stress(self, sg):
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await sg.detect_stress("https://example.com")

        assert result.is_stressed is True
        assert result.suggested_rate_limit < 2.0

    @pytest.mark.asyncio
    async def test_network_error_returns_no_stress(self, sg):
        """Network errors shouldn't crash the safeguard — return safe defaults."""
        import httpx
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_client_cls.return_value = mock_client

            result = await sg.detect_stress("https://offline-host.example.com")

        assert isinstance(result, StressLevel)
        assert result.suggested_rate_limit > 0
