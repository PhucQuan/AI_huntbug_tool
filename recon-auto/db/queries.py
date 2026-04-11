"""
db/queries.py — Reusable SQL Query Helpers
==========================================
Tách query helpers ra khỏi knowledge_graph.py để code gọn hơn.
Tất cả hàm đều dùng aiosqlite (async).
"""

import json
from datetime import datetime, timezone
from typing import Any

import aiosqlite

# ── Path mặc định (override qua argument nếu cần) ─────────────────────────
DEFAULT_DB = "db/recon.db"


# =============================================================================
# Subdomain Queries
# =============================================================================

async def insert_subdomain(
    db_path: str,
    target_id: int,
    subdomain: str,
    source: str,
    status: str = "unknown",
) -> int:
    """Thêm subdomain mới, bỏ qua nếu đã tồn tại (ON CONFLICT IGNORE)."""
    sql = """
        INSERT OR IGNORE INTO subdomains (target_id, subdomain, source, status, discovered_at)
        VALUES (?, ?, ?, ?, ?)
    """
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(sql, (target_id, subdomain, source, status, now))
        await db.commit()
        return cursor.lastrowid


async def get_subdomains(db_path: str, target_id: int) -> list[dict]:
    """Lấy tất cả subdomains của một target."""
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM subdomains WHERE target_id = ? ORDER BY discovered_at DESC",
            (target_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_subdomains_since(db_path: str, target_id: int, since_iso: str) -> list[dict]:
    """Lấy subdomains được discover AFTER một timestamp — dùng cho delta detection."""
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM subdomains WHERE target_id = ? AND discovered_at > ?",
            (target_id, since_iso),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


# =============================================================================
# Alive Host Queries
# =============================================================================

async def upsert_alive_host(db_path: str, data: dict) -> None:
    """
    Insert hoặc update alive host.
    data = { target_id, url, status_code, title, technologies (list), waf, screenshot_path }
    """
    sql = """
        INSERT INTO alive_hosts (target_id, url, status_code, title, technologies, waf, screenshot_path, checked_at)
        VALUES (:target_id, :url, :status_code, :title, :technologies, :waf, :screenshot_path, :checked_at)
        ON CONFLICT(url) DO UPDATE SET
            status_code    = excluded.status_code,
            title          = excluded.title,
            technologies   = excluded.technologies,
            waf            = excluded.waf,
            screenshot_path= excluded.screenshot_path,
            checked_at     = excluded.checked_at
    """
    data.setdefault("checked_at", datetime.now(timezone.utc).isoformat())
    if isinstance(data.get("technologies"), list):
        data["technologies"] = json.dumps(data["technologies"])

    async with aiosqlite.connect(db_path) as db:
        await db.execute(sql, data)
        await db.commit()


async def get_alive_hosts(db_path: str, target_id: int) -> list[dict]:
    """Lấy tất cả alive hosts của một target."""
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM alive_hosts WHERE target_id = ? ORDER BY checked_at DESC",
            (target_id,),
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
            # Deserialise JSON fields
            for r in rows:
                if isinstance(r.get("technologies"), str):
                    try:
                        r["technologies"] = json.loads(r["technologies"])
                    except json.JSONDecodeError:
                        r["technologies"] = []
            return rows


# =============================================================================
# Finding Queries
# =============================================================================

async def insert_finding(db_path: str, finding: dict) -> int:
    """
    Insert một finding, deduplicate theo (url, template_id).
    finding keys: target_id, url, template_id, name, severity, description,
                  matched_at, request, response, ai_severity, ai_business_impact,
                  ai_bounty_estimate, is_false_positive
    """
    sql = """
        INSERT OR IGNORE INTO findings
            (target_id, url, template_id, name, severity, description,
             matched_at, request, response, discovered_at)
        VALUES
            (:target_id, :url, :template_id, :name, :severity, :description,
             :matched_at, :request, :response, :discovered_at)
    """
    finding.setdefault("discovered_at", datetime.now(timezone.utc).isoformat())
    finding.setdefault("matched_at", "")
    finding.setdefault("request", "")
    finding.setdefault("response", "")
    finding.setdefault("template_id", "manual")

    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(sql, finding)
        await db.commit()
        return cursor.lastrowid


async def get_findings(
    db_path: str,
    target_id: int,
    severity: str | None = None,
    exclude_fp: bool = True,
) -> list[dict]:
    """
    Lấy findings của một target.
    severity: "high,critical" — lọc theo severity (comma-separated)
    exclude_fp: loại bỏ false positives
    """
    conditions = ["target_id = ?"]
    params: list[Any] = [target_id]

    if severity:
        placeholders = ",".join("?" * len(severity.split(",")))
        conditions.append(f"severity IN ({placeholders})")
        params.extend(severity.split(","))

    if exclude_fp:
        conditions.append("(is_false_positive = 0 OR is_false_positive IS NULL)")

    where = " AND ".join(conditions)
    sql = f"SELECT * FROM findings WHERE {where} ORDER BY severity DESC, discovered_at DESC"

    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, params) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def update_finding_ai_fields(db_path: str, finding_id: int, ai_data: dict) -> None:
    """Cập nhật AI enrichment fields sau khi triage xong."""
    sql = """
        UPDATE findings SET
            ai_severity         = :ai_severity,
            ai_business_impact  = :ai_business_impact,
            ai_bounty_estimate  = :ai_bounty_estimate,
            is_false_positive   = :is_false_positive
        WHERE id = :id
    """
    ai_data["id"] = finding_id
    async with aiosqlite.connect(db_path) as db:
        await db.execute(sql, ai_data)
        await db.commit()


async def mark_false_positive(db_path: str, finding_id: int) -> None:
    """Đánh dấu một finding là false positive."""
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "UPDATE findings SET is_false_positive = 1 WHERE id = ?", (finding_id,)
        )
        await db.commit()


# =============================================================================
# Target Queries
# =============================================================================

async def get_or_create_target(db_path: str, program_name: str, domain: str) -> int:
    """Tìm hoặc tạo target, trả về target_id."""
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row

        async with db.execute(
            "SELECT id FROM targets WHERE domain = ?", (domain,)
        ) as cur:
            row = await cur.fetchone()
            if row:
                return row["id"]

        cursor = await db.execute(
            "INSERT INTO targets (program_name, domain, created_at) VALUES (?, ?, ?)",
            (program_name, domain, datetime.now(timezone.utc).isoformat()),
        )
        await db.commit()
        return cursor.lastrowid


async def list_targets(db_path: str) -> list[dict]:
    """Liệt kê tất cả targets đã lưu trong DB."""
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM targets ORDER BY created_at DESC") as cur:
            return [dict(r) for r in await cur.fetchall()]
