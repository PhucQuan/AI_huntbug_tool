import asyncio
import json
import re
from datetime import datetime
from typing import List, Dict, Any, Optional

import httpx
import aiosqlite

class KnowledgeGraph:
    """
    A relational intelligence database for tracking targets, assets,
    technologies, CVEs, and their complex relationships.
    """

    def __init__(self, db_path: str = "recon_auto.db"):
        self.db_path = db_path

    async def init_db(self):
        """Initializes the full schema for the intelligence graph."""
        async with aiosqlite.connect(self.db_path) as db:
            # 1. Targets
            await db.execute("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_name TEXT,
                    company_type TEXT,
                    has_pii BOOLEAN,
                    has_payment BOOLEAN,
                    bounty_range TEXT,
                    added_at TIMESTAMP
                )
            """)
            # 2. Assets
            await db.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER REFERENCES targets(id),
                    asset_type TEXT,
                    value TEXT,
                    discovered_at TIMESTAMP,
                    last_seen TIMESTAMP,
                    status TEXT
                )
            """)
            # 3. Technologies
            await db.execute("""
                CREATE TABLE IF NOT EXISTS technologies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE,
                    version TEXT,
                    category TEXT
                )
            """)
            # 4. Asset-Technology Mapping
            await db.execute("""
                CREATE TABLE IF NOT EXISTS asset_technologies (
                    asset_id INTEGER REFERENCES assets(id),
                    tech_id INTEGER REFERENCES technologies(id),
                    confidence FLOAT,
                    detected_at TIMESTAMP,
                    PRIMARY KEY (asset_id, tech_id)
                )
            """)
            # 5. CVEs
            await db.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE,
                    cvss_score FLOAT,
                    description TEXT,
                    affected_product TEXT,
                    affected_version TEXT,
                    exploit_available BOOLEAN
                )
            """)
            # 6. Asset-CVE Mapping
            await db.execute("""
                CREATE TABLE IF NOT EXISTS asset_cves (
                    asset_id INTEGER REFERENCES assets(id),
                    cve_id INTEGER REFERENCES cves(id),
                    verified BOOLEAN DEFAULT FALSE,
                    PRIMARY KEY (asset_id, cve_id)
                )
            """)
            # 7. Relationships (The Graph)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS relationships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER REFERENCES assets(id),
                    target_id INTEGER REFERENCES assets(id),
                    relationship TEXT,
                    metadata TEXT
                )
            """)
            await db.commit()

    # --- Core CRUD ---

    async def add_target(self, data: Dict[str, Any]) -> int:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                INSERT INTO targets (program_name, company_type, has_pii, has_payment, bounty_range, added_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                data.get('program_name'),
                data.get('company_type'),
                1 if data.get('has_pii') else 0,
                1 if data.get('has_payment') else 0,
                data.get('bounty_range'),
                datetime.now().isoformat()
            ))
            await db.commit()
            return cursor.lastrowid

    async def add_asset(self, target_id: int, asset_type: str, value: str, status: str = "alive") -> int:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                INSERT INTO assets (target_id, asset_type, value, discovered_at, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (target_id, asset_type, value, datetime.now().isoformat(), datetime.now().isoformat(), status))
            await db.commit()
            return cursor.lastrowid

    async def link_tech_to_asset(self, asset_id: int, tech_name: str, version: str = None, category: str = "unknown", confidence: float = 1.0):
        async with aiosqlite.connect(self.db_path) as db:
            # 1. Ensure tech exists
            await db.execute("""
                INSERT OR IGNORE INTO technologies (name, version, category) VALUES (?, ?, ?)
            """, (tech_name, version, category))

            # 2. Get tech_id
            async with db.execute("SELECT id FROM technologies WHERE name = ?", (tech_name,)) as cursor:
                row = await cursor.fetchone()
                if not row: return
                tech_id = row[0]

            # 3. Link to asset
            await db.execute("""
                INSERT OR REPLACE INTO asset_technologies (asset_id, tech_id, confidence, detected_at)
                VALUES (?, ?, ?, ?)
            """, (asset_id, tech_id, confidence, datetime.now().isoformat()))
            await db.commit()

    # --- Power Queries ---

    async def find_assets_by_tech(self, tech_name: str, version: str = None) -> List[Dict[str, Any]]:
        """Cross-target query: Find all assets using a specific technology/version."""
        query = """
            SELECT a.id, a.value, t.program_name, tech.name, tech.version
            FROM assets a
            JOIN asset_technologies at ON a.id = at.asset_id
            JOIN technologies tech ON at.tech_id = tech.id
            JOIN targets t ON a.target_id = t.id
            WHERE tech.name LIKE ?
        """
        params = [f"%{tech_name}%"]

        if version:
            query += " AND tech.version LIKE ?"
            params.append(f"%{version}%")

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def get_attack_surface(self, target_id: int) -> Dict[str, Any]:
        """Returns a full mapped view of a target's attack surface."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            # 1. Subdomains/Assets
            async with db.execute("SELECT value, status FROM assets WHERE target_id = ? AND asset_type = 'subdomain'", (target_id,)) as cursor:
                assets = [dict(r) for r in await cursor.fetchall()]

            # 2. Tech Stack
            async with db.execute("""
                SELECT tech.name, tech.version
                FROM technologies tech
                JOIN asset_technologies at ON tech.id = at.tech_id
                JOIN assets a ON at.asset_id = a.id
                WHERE a.target_id = ?
            """, (target_id,)) as cursor:
                techs = [f"{r['name']} {r['version'] or ''}" for r in await cursor.fetchall()]

            # 3. CVEs
            async with db.execute("""
                SELECT c.cve_id, c.cvss_score
                FROM cves c
                JOIN asset_cves ac ON c.id = ac.cve_id
                JOIN assets a ON ac.asset_id = a.id
                WHERE a.target_id = ?
            """, (target_id,)) as cursor:
                cves = [f"{r['cve_id']} (CVSS {r['cvss_score']})" for r in await cursor.fetchall()]

            return {
                "assets": assets,
                "tech_stack": list(set(techs)),
                "exposed_cves": cves
            }

    async def enrich_with_cves(self, asset_id: int, technologies: List[Dict[str, Any]]):
        """Automatically lookup and link CVEs from NVD."""
        for tech in technologies:
            name = tech.get('name')
            version = tech.get('version')
            if not name: continue

            # Query NVD API (simplified)
            query = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={name}+{version}"

            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(query, timeout=10.0)
                    if resp.status_code == 200:
                        data = resp.json()
                        for vuln in data.get('vulnerabilities', []):
                            cve_data = vuln.get('cve', {})
                            cve_id = cve_data.get('id')
                            cvss = cve_data.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0.0)

                            # 1. Save CVE to DB
                            async with aiosqlite.connect(self.db_path) as db:
                                await db.execute("""
                                    INSERT OR IGNORE INTO cves (cve_id, cvss_score, description, affected_product, affected_version)
                                    VALUES (?, ?, ?, ?, ?)
                                """, (cve_id, cvss, cve_data.get('descriptions', [{}])[0].get('value'), name, version))
                                await db.commit()

                                # 2. Link to Asset
                                await db.execute("""
                                    INSERT OR IGNORE INTO asset_cves (asset_id, cve_id, verified)
                                    VALUES (?, ?, ?)
                                """, (asset_id, cve_id, False))
                                await db.commit()
            except Exception as e:
                print(f"[!] CVE Enrichment error for {name}: {e}")

    async def get_new_assets_since(self, target_id: int, since_iso: str) -> List[Dict[str, Any]]:
        """Delta query for monitoring."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM assets WHERE target_id = ? AND discovered_at > ?",
                (target_id, since_iso)
            ) as cursor:
                return [dict(r) for r in await cursor.fetchall()]

    async def find_similar_targets(self, tech_stack: List[str]) -> List[Dict[str, Any]]:
        """Finds targets sharing multiple technologies from a given tech_stack."""
        if not tech_stack: return []
        placeholders = ','.join(['?']*len(tech_stack))
        query = f"""
            SELECT t.id, t.program_name, COUNT(DISTINCT tech.name) as match_count
            FROM targets t
            JOIN assets a ON t.id = a.target_id
            JOIN asset_technologies at ON a.id = at.asset_id
            JOIN technologies tech ON at.tech_id = tech.id
            WHERE tech.name IN ({placeholders})
            GROUP BY t.id
            ORDER BY match_count DESC
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, tech_stack) as cursor:
                return [dict(r) for r in await cursor.fetchall()]

    async def visualize_ascii(self, target_id: int) -> str:
        """Generates an ASCII tree of the attack surface mapping."""
        surface = await self.get_attack_surface(target_id)
        if not surface: return "Target not found or empty."
        
        lines = [f"Target ID: {target_id}"]
        # This is a simplified ASCII generator
        for asset in surface.get('assets', []):
            val = asset.get('value', 'Unknown')
            status = asset.get('status', 'unknown')
            lines.append(f"├── {val} [{status}]")
            
            # Sub points for tech could be fetched by asset, but here we just list global tech
            for tech in surface.get('tech_stack', []):
                lines.append(f"│   ├── {tech}")
            for cve in surface.get('exposed_cves', []):
                lines.append(f"│   └── ⚠ {cve}")
                
        return "\n".join(lines)
