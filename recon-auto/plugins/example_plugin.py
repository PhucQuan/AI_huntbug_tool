"""
Example Plugin — Custom Error-Based SQLi Scanner
=================================================
Đây là ví dụ minh hoạ cách viết một custom plugin cho recon-auto.

Cách dùng:
  1. Copy file này vào thư mục plugins/
  2. Rename sang tên plugin của bạn (vd: my_sqli_scanner.py)
  3. Implement logic trong hàm run()
  4. Chạy: python main.py scan -d target.com --plugin custom_sqli_error_based
  5. Hoặc để chạy tự động: tool sẽ auto-load tất cả plugin trong plugins/

Plugin sẽ được tự động phát hiện bởi core/plugins/loader.py
"""

import asyncio
import httpx
from core.plugins.base import BasePlugin, Target, Finding


class ExampleSQLiPlugin(BasePlugin):
    """
    Demo plugin: thử các payload SQLi cơ bản dựa vào error-based technique.
    Chỉ dùng để học cách viết plugin — KHÔNG dùng trong production.
    """

    name        = "custom_sqli_error_based"
    description = "Custom error-based SQLi with basic WAF bypass payloads"
    stage       = "scan"
    author      = "yourhandle"
    version     = "1.0.0"
    requires    = []              # Không cần tool binary nào thêm

    # ── Payloads ──────────────────────────────────────────────────────────
    # Chỉ dùng detection payload — không phải exploit payload
    DETECTION_PAYLOADS = [
        "'",
        "\"",
        "1' AND '1'='1",
        "1 AND 1=1--",
        "' OR SLEEP(5)--",
    ]

    # Strings xuất hiện trong response body khi có SQL error
    ERROR_SIGNATURES = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "pg_query(): query failed",
        "sqlstate",
        "ora-0",
        "microsoft ole db provider for sql server",
    ]

    # ── Core Logic ────────────────────────────────────────────────────────
    async def run(self, target: Target) -> list[Finding]:
        """
        Với mỗi URL trong target.urls:
        - Nếu URL không trong scope → bỏ qua
        - Thêm payload vào query params
        - Kiểm tra response body xem có SQL error không
        """
        findings = []

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for url in target.urls:
                # Luôn check scope trước khi gửi bất kỳ request nào!
                if not self.is_in_scope(url, target.scope):
                    continue

                # Thêm payload vào query string
                for payload in self.DETECTION_PAYLOADS:
                    test_url = self._inject_payload(url, payload)
                    try:
                        resp = await client.get(test_url)
                        body = resp.text.lower()

                        # Kiểm tra error signature
                        for sig in self.ERROR_SIGNATURES:
                            if sig in body:
                                findings.append(Finding(
                                    url=test_url,
                                    vulnerability_type="sqli",
                                    severity="high",
                                    description=(
                                        f"Potential error-based SQLi detected.\n"
                                        f"Error signature found: '{sig}'\n"
                                        f"Payload used: {payload}"
                                    ),
                                    request=f"GET {test_url}",
                                    response=resp.text[:500],   # Truncate để tiết kiệm DB
                                    payload=payload,
                                ))
                                break  # Tìm thấy rồi, không thử payload tiếp

                    except (httpx.RequestError, asyncio.TimeoutError):
                        pass  # Skip lỗi mạng — không crash tool

                # Rate limit: tránh hammer server
                await asyncio.sleep(0.5)

        return findings

    # ── Helpers ───────────────────────────────────────────────────────────
    def _inject_payload(self, url: str, payload: str) -> str:
        """
        Thêm payload vào query string.
        Nếu URL đã có params → thêm vào param đầu tiên.
        Nếu không có → thêm ?id=<payload>
        """
        if "?" in url and "=" in url:
            # Thêm payload vào sau value của param đầu tiên
            base, query = url.split("?", 1)
            params = query.split("&")
            first_key, *rest = params[0].split("=", 1)
            injected = f"{first_key}={payload}"
            new_query = "&".join([injected] + params[1:])
            return f"{base}?{new_query}"
        else:
            return f"{url}?id={payload}"
