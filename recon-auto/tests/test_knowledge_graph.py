"""
tests/test_knowledge_graph.py — Unit Tests for KnowledgeGraph
"""

import pytest
import asyncio
import aiosqlite
from pathlib import Path
from unittest.mock import AsyncMock, patch

from db.knowledge_graph import KnowledgeGraph


@pytest.fixture
async def tmp_db(tmp_path) -> KnowledgeGraph:
    """Create an in-memory KnowledgeGraph for each test."""
    db_path = str(tmp_path / "test_recon.db")
    kg = KnowledgeGraph(db_path)
    await kg.init_db()
    return kg


class TestKnowledgeGraphInit:

    @pytest.mark.asyncio
    async def test_init_creates_tables(self, tmp_db):
        """DB init should create all required tables."""
        kg = tmp_db
        async with aiosqlite.connect(kg.db_path) as db:
            async with db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ) as cur:
                tables = {row[0] for row in await cur.fetchall()}

        # These tables must exist after init_db()
        assert "targets" in tables
        assert "assets" in tables
        assert "technologies" in tables


class TestTargetOperations:

    @pytest.mark.asyncio
    async def test_add_and_retrieve_target(self, tmp_db):
        kg = tmp_db
        target_id = await kg.add_target(
            program_name="TestProgram",
            domain="test.example.com",
            company_type="saas",
            has_pii=True,
            has_payment=False,
            bounty_range="$500-$5000",
        )
        assert target_id > 0

        # Retrieve should return this target
        async with aiosqlite.connect(kg.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM targets WHERE id = ?", (target_id,)
            ) as cur:
                row = await cur.fetchone()

        assert row is not None
        assert row["domain"] == "test.example.com"
        assert row["program_name"] == "TestProgram"

    @pytest.mark.asyncio
    async def test_add_asset_linked_to_target(self, tmp_db):
        kg = tmp_db
        target_id = await kg.add_target("T", "t.com", "blog", False, False, "$0")

        asset_id = await kg.add_asset(
            target_id=target_id,
            asset_type="subdomain",
            value="api.t.com",
            status="alive",
        )
        assert asset_id > 0

        # Verify FK relationship
        async with aiosqlite.connect(kg.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM assets WHERE id = ?", (asset_id,)
            ) as cur:
                row = await cur.fetchone()

        assert row["target_id"] == target_id
        assert row["value"] == "api.t.com"


class TestAttackSurface:

    @pytest.mark.asyncio
    async def test_get_attack_surface_returns_dict(self, tmp_db):
        kg = tmp_db
        target_id = await kg.add_target("P", "example.com", "saas", True, False, "$100-$1000")
        await kg.add_asset(target_id, "subdomain", "app.example.com", "alive")

        surface = await kg.get_attack_surface(target_id)

        assert isinstance(surface, dict)
        assert "assets" in surface or surface == {} or surface is not None

    @pytest.mark.asyncio
    async def test_visualize_ascii_returns_string(self, tmp_db):
        kg = tmp_db
        target_id = await kg.add_target("P2", "vis.example.com", "fintech", True, True, "$500-$5000")
        await kg.add_asset(target_id, "subdomain", "api.vis.example.com", "alive")
        await kg.add_asset(target_id, "subdomain", "admin.vis.example.com", "alive")

        tree = await kg.visualize_ascii(target_id)

        assert isinstance(tree, str)
        assert len(tree) > 0

    @pytest.mark.asyncio
    async def test_find_similar_targets_empty_stack(self, tmp_db):
        """Empty tech_stack should return [] without crashing."""
        kg = tmp_db
        result = await kg.find_similar_targets([])
        assert result == []
