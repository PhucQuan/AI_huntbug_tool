# recon-auto 🎯

> **AI-Powered Bug Bounty Automation Framework**  
> Tự động hóa toàn bộ pipeline từ recon → vuln scan → AI triage → report  
> Built for serious bug bounty hunters. Not just another wrapper.

---

## 📋 Table of Contents

- [Tổng quan](#tổng-quan)
- [Kiến trúc](#kiến-trúc)
- [Tính năng](#tính-năng)
- [Cài đặt](#cài-đặt)
- [Cấu hình](#cấu-hình)
- [Hướng dẫn sử dụng](#hướng-dẫn-sử-dụng)
- [Plugin System](#plugin-system)
- [AI Integration](#ai-integration)
- [Modules chi tiết](#modules-chi-tiết)
- [Cấu trúc project](#cấu-trúc-project)
- [Testing](#testing)
- [Ethical Guidelines](#ethical-guidelines)
- [Roadmap](#roadmap)

---

## Tổng quan

`recon-auto` là một CLI framework tự động hóa bug bounty hunting, tích hợp AI để:

- Chạy song song nhiều recon tool (subfinder, amass, assetfinder, httpx, nuclei...)
- Phân tích kết quả bằng AI với **contextual scoring** — severity được đánh giá theo business context thực tế, không chỉ dựa CVSS
- Filter false positive tự động trước khi alert
- Gợi ý attack chain khi có nhiều finding kết hợp được
- Tự động generate báo cáo chuẩn HackerOne format
- Monitor liên tục, alert ngay khi có subdomain/endpoint mới

```
Điểm khác biệt so với tool thông thường:
─────────────────────────────────────────────────
Tool thông thường          recon-auto
──────────────────────     ──────────────────────
Wrapper đơn giản           Plugin architecture
Lưu text file              Knowledge graph (SQLite)
Chạy một lần               Continuous monitoring
Wordlist generic           Smart wordlist generation
Không có test              Unit + integration tests
Severity theo CVSS         AI contextual scoring
Báo false positive nhiều   AI false positive filter
──────────────────────     ──────────────────────
```

---

## Kiến trúc

```
Target Domain
      │
      ▼
┌─────────────────────────────────────────┐
│           Stage 1: Recon                │
│  subfinder + amass + assetfinder        │
│  → httpx alive check + tech detect      │
│  → gowitness screenshot                 │
│  → wafw00f WAF detect                   │
│  → Smart wordlist generation (AI)       │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│        Stage 2: Vuln Scan               │
│  nuclei (safe → medium → tech-specific) │
│  → dalfox XSS                           │
│  → ffuf / dirsearch fuzzing             │
│  → corsy CORS, crlfuzz, testssl         │
│  → ssrfmap, smuggler                    │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│        Stage 3: AI Triage               │
│  Rule-based false positive filter       │
│  → AI contextual severity scoring       │
│  → Attack chain suggestion              │
│  → Bounty estimate                      │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│        Stage 4: Report                  │
│  AI generate HackerOne format report    │
│  → CVSS score calculation               │
│  → Export Markdown + PDF                │
└─────────────────────────────────────────┘
```

---

## Tính năng

### 🔍 Recon
- **Subdomain enumeration** song song: subfinder, amass, assetfinder, **findomain**
- **Passive sources**: crt.sh, Wayback Machine, VirusTotal API, GitHub scraping
- **Subdomain takeover check**: fingerprint CNAME với GitHub Pages, Heroku, Netlify, AWS S3... (12+ services)
- **Alive check + tech detection**: httpx với status code, title, tech stack
- **WAF detection**: wafw00f tự động
- **Port scan**: naabu (fast) + nmap (detailed) + masscan (ultra-fast)
- **Screenshot**: gowitness chụp ảnh toàn bộ alive host
- **URL collection**: gau, katana, hakrawler, urlfinder (active + passive)
- **Parameter discovery**: arjun fuzzing + gf patterns (XSS, SQLi, LFI, SSRF, etc.)
- **JS analysis**: Extract endpoints, API keys, secrets, tokens từ JS files
- **.git exposure**: Automated detection + git-dumper extraction
- **Cert transparency monitoring**: poll crt.sh để biết subdomain mới trước khi public

### 🎯 Smart Wordlist Generation
- Crawl target → extract words từ HTML, JS, comments
- AI phân tích naming convention của target (kebab-case, versioning pattern...)
- Generate custom wordlist tailored riêng cho target
- Tự động detect tech stack → thêm paths phù hợp (WordPress, Laravel, Django, Spring...)

### 🔬 Vuln Scan
- **Nuclei**: chạy theo phase (safe → medium → tech-specific)
- **XSS**: dalfox với blind XSS support
- **SQL Injection**: sqlmap + manual error-based detection
- **Directory brute force**: ffuf + dirsearch với custom wordlist
- **CORS misconfig**: corsy
- **CRLF injection**: crlfuzz
- **SSL/TLS analysis**: testssl.sh
- **Open redirect**: oralyzer
- **SSRF**: ssrfmap + interactsh OOB
- **HTTP smuggling**: smuggler
- **Prototype pollution**: ppmap
- **Subdomain takeover**: subzy + manual verification
- **.git exposure**: Automated detection & extraction

### 🤖 AI-Powered Triage (Gemini)
- **Contextual scoring**: severity theo business context (fintech ≠ blog)
- **False positive filter**: rule-based trước, AI verify khi uncertain
- **Attack chain suggestion**: combine nhiều finding → impact cao hơn
- **Bounty estimate**: ước tính bounty dựa trên program history
- **Powered by Google Gemini**: Free tier, faster response, multilingual support

### 📊 Recon Intelligence Database
- Knowledge graph lưu relationship: target → subdomain → technology → CVE
- Cross-target query: "tất cả target đang dùng Apache 2.4.49"
- CVE enrichment tự động từ NVD API
- ASCII tree visualization trong terminal

### 📝 Auto Report Generation
- Generate báo cáo chuẩn HackerOne format bằng AI
- Tự tính CVSS 3.1 score
- Export Markdown + PDF
- Hỗ trợ nhiều platform format: HackerOne, Bugcrowd, Intigriti

### 🔄 Continuous Monitoring
- Chạy recon hàng ngày, chỉ alert khi có **gì đó mới**
- Delta detection: subdomain mới, endpoint mới trong JS, SSL cert mới
- Khi phát hiện subdomain mới → tự động scan ngay lập tức
- Alert qua Slack / Telegram

### 🔌 Plugin Architecture
- Viết custom scanner bằng cách kế thừa `BasePlugin`
- Drop file vào `plugins/` → tự động được load
- Không cần sửa core code

---

## Cài đặt

### Yêu cầu hệ thống
- Python 3.11+
- Go 1.21+ (cho các tool ProjectDiscovery)
- Linux / macOS (khuyến nghị Kali Linux hoặc Ubuntu)

### Bước 1: Clone repo

```bash
git clone https://github.com/yourhandle/recon-auto
cd recon-auto
```

### Bước 2: Cài Python dependencies

```bash
pip install -r requirements.txt
```

```
# requirements.txt
google-generativeai  # Gemini AI (thay thế anthropic)
rich
click
apscheduler
reportlab
weasyprint
aiohttp
aiofiles
httpx
beautifulsoup4
pytest
pytest-asyncio
pytest-cov
```

### Bước 3: Cài external tools

```bash
# ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Other tools
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/sensepost/gowitness@latest
go install -v github.com/s0md3v/uro@latest
go install -v github.com/hakluke/hakrawler@latest
go install -v github.com/PentestPad/subzy@latest

# findomain (binary release)
wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux
chmod +x findomain-linux
sudo mv findomain-linux /usr/local/bin/findomain

# pip tools
pip install wafw00f
pip install dirsearch
pip install arjun
pip install git-dumper
pip install sqlmap

# apt tools (Kali/Ubuntu)
sudo apt install nmap amass ffuf masscan -y

# Nuclei templates
nuclei -update-templates
```

### Bước 4: Cài đặt môi trường

```bash
cp config/targets.example.yaml config/targets.yaml

# Set API keys
export GEMINI_API_KEY="AIzaSy..."  # Get free at https://makersuite.google.com/app/apikey
export VIRUSTOTAL_API_KEY="..."   # optional
export GITHUB_TOKEN="ghp_..."      # optional
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."  # optional

# Hoặc tạo file .env
cp .env.example .env
# Edit .env và điền API keys
```

### Bước 5: Init database

```bash
python main.py --init-db
```

---

## Cấu hình

### config/targets.yaml

```yaml
targets:
  - program_name: "HackerOne"
    domain: "hackerone.com"
    company_type: "saas"        # saas / fintech / healthcare / ecommerce / blog
    has_pii: true
    has_payment: false
    bounty_range: "$500-$10000"
    scope:
      - "*.hackerone.com"
      - "hackerone.com"
    out_of_scope:
      - "blog.hackerone.com"
      - "*.hackerone.net"
    schedule: "daily"           # daily / weekly / manual
    
  - program_name: "Bugcrowd Example"
    domain: "example.com"
    company_type: "fintech"
    has_pii: true
    has_payment: true
    bounty_range: "$100-$5000"
    scope:
      - "app.example.com"
      - "api.example.com"
    out_of_scope: []
    schedule: "weekly"

settings:
  rate_limit: 2                 # requests/second per target (default)
  max_concurrent_tools: 3       # tool chạy song song tối đa
  screenshot: true              # có chụp screenshot không
  ai_triage: true               # có dùng AI triage không
  slack_alerts: true
  alert_severity_threshold: "medium"   # chỉ alert từ medium trở lên
  nuclei_severity: "medium,high,critical"
```

---

## Hướng dẫn sử dụng

### Chạy full pipeline

```bash
# Full pipeline: recon + scan + AI triage + report
python main.py -d hackerone.com --mode full

# Chỉ recon (subdomain + alive check + screenshot)
python main.py -d hackerone.com --mode recon

# Chỉ scan (lấy subdomains từ DB đã recon trước)
python main.py -d hackerone.com --mode scan --from-db

# Xem verbose output (raw output của từng tool)
python main.py -d hackerone.com --mode full --verbose
```

**Terminal output mẫu:**

```
╔══════════════════════════════════════╗
║     RECON-AUTO v1.0 | @yourhandle   ║
╚══════════════════════════════════════╝

[*] Target     : hackerone.com
[*] Mode       : Full Pipeline
[*] Started    : 2025-01-15 14:30:00

──────────── Stage 1: Subdomain Enum ────────────
[→] Running subfinder...
[→] Running amass...
[→] Running assetfinder...
[✓] subfinder      : 45 subdomains
[✓] amass          : 23 subdomains
[✓] assetfinder    : 31 subdomains
[★] Total unique   : 52 subdomains saved

──────────── Stage 2: Alive Check ────────────
[→] Running httpx on 52 hosts...
████████████████████ 100% | 52/52 hosts
[✓] Alive hosts    : 31
[✓] Technologies   : WordPress(5), Laravel(3), nginx(12)

──────────── Stage 3: Vuln Scan ────────────
[→] Running nuclei (safe templates)...
[!] FINDING [HIGH]   : admin.hackerone.com — Exposed .env file
[!] FINDING [MEDIUM] : api.hackerone.com   — Missing security headers
[→] Running XSS checks...
[!] FINDING [HIGH]   : app.hackerone.com/search?q= — Reflected XSS

──────────── Stage 4: AI Triage ────────────
[→] Sending 3 findings to Claude API...
[✓] AI analysis complete
[!] Finding #1: severity adjusted Medium → High (SaaS context, no CSP)
[✗] Finding #2: FALSE POSITIVE filtered (headers present in redirect)

──────────── Summary ────────────
┌─────────────┬───────┐
│ Severity    │ Count │
├─────────────┼───────┤
│ Critical    │     0 │
│ High        │     2 │
│ Medium      │     1 │
│ Low         │     4 │
└─────────────┴───────┘

[✓] Results saved  : results/hackerone_20250115.json
[✓] Report draft   : results/hackerone_report_draft.md
[✓] Total time     : 8m 32s
```

### Report generation

```bash
# Generate report cho finding cụ thể
python main.py report --finding-id 3

# Preview trong terminal không export file
python main.py report --finding-id 3 --preview

# Generate tất cả findings chưa có report
python main.py report --all --output reports/

# Export PDF (thêm --final để bỏ watermark DRAFT)
python main.py report --finding-id 3 --format pdf --final
```

### Query database

```bash
# Xem tất cả subdomains của target
python main.py show -d hackerone.com --type subdomains

# Xem findings, filter theo severity
python main.py show -d hackerone.com --type findings --severity high,critical

# Knowledge graph: tìm target đang dùng tech cụ thể
python main.py graph --query tech --name wordpress --version "5.*"

# Tìm CVE đang affect target nào
python main.py graph --query cve --min-cvss 7.0

# Visualize attack surface dạng ASCII tree
python main.py graph -d hackerone.com --visualize
```

**Output visualize mẫu:**

```
hackerone.com
├── api.hackerone.com [alive]
│   ├── nginx 1.18.0
│   ├── ⚠ CVE-2021-23017 (CVSS 7.7)
│   └── behind: Cloudflare
├── admin.hackerone.com [alive]
│   ├── WordPress 5.8
│   ├── ⚠ CVE-2021-44223 (CVSS 5.4)
│   └── WAF: Cloudflare
└── old.hackerone.com [dead]
```

### Smart wordlist

```bash
# Generate custom wordlist cho target
python main.py wordlist -d hackerone.com

# Generate rồi dùng ngay cho scan
python main.py wordlist -d hackerone.com --use-for-scan
```

### Monitoring

```bash
# Chạy scheduler daemon (chạy ngầm)
python main.py monitor --start

# Force check ngay lập tức
python main.py monitor --check-now

# Xem status các jobs đang chạy
python main.py monitor --status

# Xem tất cả thay đổi trong 7 ngày qua
python main.py monitor --diff --since 7d
```

### Delta detection output mẫu

```
[!] 02:47:13 NEW SUBDOMAIN: staging-api.hackerone.com
[→] 02:47:14 Auto-scanning new asset...
[✓] 02:47:45 Alive (200) | Laravel 8.x | No WAF
[!] 02:48:12 FINDING: staging-api exposed debug endpoint /.env
[★] 02:48:13 Alert sent to Slack
```

---

## Plugin System

Bất kỳ ai cũng có thể viết custom scanner mà không cần sửa core code.

### Tạo plugin mới

```python
# plugins/my_custom_scanner.py
from core.plugins.base import BasePlugin, Target, Finding

class MyCustomScanner(BasePlugin):
    name = "custom_sqli_error_based"
    description = "Custom error-based SQLi with WAF bypass payloads"
    stage = "scan"
    author = "yourhandle"
    version = "1.0.0"
    requires = ["sqlmap"]       # tool dependencies
    
    PAYLOADS = [
        "' OR '1'='1",
        "1' AND SLEEP(5)--",
    ]
    
    async def run(self, target: Target) -> list[Finding]:
        findings = []
        for url in target.urls:
            if not self.is_in_scope(url, target.scope):
                continue
            for payload in self.PAYLOADS:
                result = await self._test_payload(url, payload)
                if result:
                    findings.append(Finding(
                        url=url,
                        vulnerability_type="sqli",
                        severity="high",
                        description=f"Error-based SQLi via payload: {payload}",
                        payload=payload,
                    ))
        return findings
```

Drop file vào `plugins/` → tự động được load khi chạy scan.

```bash
# List tất cả plugins đã load
python main.py plugins --list

# Chạy chỉ plugin cụ thể
python main.py scan -d target.com --plugin custom_sqli_error_based
```

---

## AI Integration

### Contextual Triage

AI triage không chỉ hỏi "có nguy hiểm không" mà phân tích theo business context:

```
SSRF trên fintech với internal AWS access = Critical
SSRF trên blog cá nhân                    = Low

XSS trên banking portal (có 2FA flow)     = High  
XSS trên static marketing site            = Low
```

### False Positive Filter

Pipeline 2 bước để tiết kiệm API cost:

```
Finding từ nuclei
      │
      ▼
Rule-based check (nhanh, miễn phí)
  - XSS: có CSP strict? response là JSON? payload bị encode?
  - SQLi: response time < 4s cho time-based?
  - SSRF: có OOB callback không?
      │
      ├── Kết luận rõ ràng → alert hoặc discard
      │
      └── Uncertain → gọi AI verify (tốn API cost)
```

### Attack Chain Suggestion

```
Findings đơn lẻ:
  #3: LFI (Medium)
  #7: File Upload (Low)

AI gợi ý chain:
  [!] CHAIN: LFI → PHP session → RCE
      Step 1: Dùng LFI (#3) đọc /tmp/sess_* files
      Step 2: Extract serialized session data
      Step 3: Dùng file upload (#7) plant PHP payload
      Step 4: Trigger deserialization → RCE
      Combined severity: CRITICAL
```

---

## Modules chi tiết

### core/recon/subdomain.py
- `enumerate_subdomains(domain)` — chạy subfinder + amass + assetfinder + findomain + passive sources
- `check_takeover(subdomain)` — fingerprint CNAME check
- `SubdomainDB` — CRUD SQLite

### core/recon/passive_sources.py
- `fetch_crtsh(domain)` — Certificate Transparency logs
- `fetch_wayback(domain)` — Wayback Machine CDX API
- `fetch_virustotal(domain, api_key)` — VirusTotal subdomains
- `fetch_github_subdomains(domain, token)` — GitHub scraping
- `run_passive_sources(domain)` — orchestrator chạy tất cả

### core/recon/url_collection.py
- `run_gau(domains)` — passive URL discovery
- `run_katana(domains, depth)` — active crawling
- `run_hakrawler(domains)` — lightweight crawler
- `filter_urls_with_params(urls)` — lọc URLs có parameters
- `filter_sensitive_files(urls)` — lọc .env, .git, .bak, etc.
- `filter_js_files(urls)` — lọc JavaScript files

### core/recon/param_discovery.py
- `run_arjun(url, methods)` — hidden parameter fuzzing
- `apply_gf_pattern(urls, pattern)` — XSS/SQLi/LFI/SSRF candidates
- `extract_params_from_urls(urls)` — extract parameter names

### core/recon/js_analysis.py
- `extract_endpoints(js_content)` — API endpoints từ JS
- `detect_secrets(js_content)` — AWS keys, tokens, passwords
- `extract_subdomains(js_content, domain)` — subdomains trong JS
- `extract_comments(js_content)` — sensitive comments

### core/recon/web_analysis.py
- `run_httpx(subdomains)` — alive check + tech detect
- `detect_waf(url)` — wafw00f wrapper
- `take_screenshots(hosts)` — gowitness wrapper
- `generate_html_gallery(screenshots)` — HTML gallery xem ảnh
- `prioritize_targets(hosts)` — sort theo priority

### core/recon/wordlist_gen.py
- `extract_words_from_target(domain)` — crawl + extract vocab
- `analyze_naming_convention(words)` — AI phân tích pattern
- `generate_subdomain_wordlist(corpus, pattern)` — custom wordlist
- `generate_path_wordlist(corpus, tech_stack)` — tech-aware paths

### core/scan/nuclei_runner.py
- `run_nuclei_phase(urls, templates, severity)` — phase-based scan
- `run_full_nuclei_pipeline(hosts)` — tự chọn template theo tech stack

### core/scan/port_scanner.py
- `run_naabu(hosts, ports, rate)` — fast port scanning
- `run_nmap(host, ports, scan_type)` — detailed service detection
- `run_masscan(hosts, ports, rate)` — ultra-fast scanning

### core/scan/sqli_scanner.py
- `filter_sqli_prone_urls(urls)` — lọc PHP/ASP/JSP với SQLi params
- `run_sqlmap(url, level, risk)` — automated SQLi detection
- `test_sqli_manual(url)` — manual error-based detection

### core/scan/takeover_scanner.py
- `run_subzy(subdomains)` — automated takeover checker
- `check_takeover_manual(subdomain)` — CNAME + fingerprint verification
- Support 12+ services: GitHub, Heroku, Netlify, S3, Shopify, etc.

### core/scan/git_exposure.py
- `check_git_exposure(base_url)` — detect exposed .git directories
- `run_git_dumper(url, output_dir)` — extract repository
- `list_sensitive_files_in_repo(repo_path)` — scan for .env, keys, credentials

### core/ai/triage.py (Gemini-powered)
- `contextual_score(finding, target_context)` — AI severity scoring với Gemini
- `verify_finding(finding)` — false positive filter
- `suggest_attack_chains(findings, tech_stack)` — chain detection
- Uses `google-generativeai` SDK với model `gemini-1.5-flash`

### core/ai/report_gen.py (Gemini-powered)
- `generate_report(finding)` — AI generate HackerOne report với Gemini
- `export_markdown(report, path)` — export .md
- `export_pdf(report, path)` — export .pdf
- `calculate_cvss(finding)` — tính CVSS 3.1 score

### db/knowledge_graph.py
- `find_assets_by_tech(tech, version)` — cross-target query
- `get_attack_surface(target_id)` — full attack surface map
- `enrich_with_cves(asset_id, technologies)` — NVD API lookup
- `visualize_ascii(target_id)` — terminal tree view

### core/monitor/delta.py
- `check_new_subdomains(target)` — daily diff check
- `check_cert_transparency(domain)` — crt.sh polling
- `check_js_endpoints(asset_id)` — JS file change detection

### core/safeguards.py
- `check_scope(url, scope, out_of_scope)` — scope validation
- `detect_stress(target)` — throttle khi target bị quá tải
- `rate_limiter(rps)` — configurable rate limiting

---

## Cấu trúc project

```
recon-auto/
├── main.py                     # CLI entry point
├── scheduler.py                # APScheduler daemon
├── requirements.txt
├── pyproject.toml
│
├── core/
│   ├── plugins/
│   │   ├── base.py             # BasePlugin abstract class
│   │   └── loader.py           # Auto-discover plugins
│   ├── recon/
│   │   ├── subdomain.py        # subfinder, amass, assetfinder, findomain
│   │   ├── passive_sources.py  # crt.sh, wayback, virustotal, github
│   │   ├── web_analysis.py     # httpx, katana, wafw00f, gowitness
│   │   ├── url_collection.py   # gau, katana, hakrawler, urlfinder
│   │   ├── param_discovery.py  # arjun, gf patterns
│   │   ├── js_analysis.py      # JS endpoint/secret extraction
│   │   └── wordlist_gen.py     # Smart wordlist generation
│   ├── scan/
│   │   ├── nuclei_runner.py    # Phase-based nuclei
│   │   ├── web_vulns.py        # XSS, CORS, SSRF, CRLF chains
│   │   ├── sqli_scanner.py     # sqlmap + manual SQLi detection
│   │   ├── port_scanner.py     # naabu, nmap, masscan
│   │   ├── takeover_scanner.py # subzy + manual takeover check
│   │   ├── git_exposure.py     # .git detection & extraction
│   │   └── fuzzer.py           # ffuf, dirsearch wrapper
│   ├── ai/
│   │   ├── triage.py           # Gemini contextual scoring + FP filter
│   │   ├── report_gen.py       # Gemini HackerOne report generation
│   │   └── wordlist_ai.py      # Naming convention analysis
│   ├── monitor/
│   │   └── delta.py            # Delta detection
│   └── safeguards.py           # Ethical safeguards
│
├── db/
│   ├── models.py               # SQLite schema
│   ├── queries.py              # Query helpers
│   └── knowledge_graph.py      # Relationship queries
│
├── plugins/                    # User-created plugins (drop here)
│   └── example_plugin.py
│
├── config/
│   ├── targets.yaml            # Target configuration
│   └── targets.example.yaml
│
├── tests/
│   ├── test_subdomain.py
│   ├── test_triage.py
│   ├── test_report_gen.py
│   ├── test_safeguards.py
│   └── test_knowledge_graph.py
│
├── reports/                    # Generated reports (gitignored)
├── results/                    # Scan results (gitignored)
├── wordlists/                  # Generated wordlists (gitignored)
├── screenshots/                # gowitness output (gitignored)
└── logs/                       # Scan logs (gitignored)
```

---

## Testing

```bash
# Chạy tất cả tests
pytest tests/ -v

# Với coverage report
pytest tests/ --cov=core --cov-report=html
open htmlcov/index.html

# Chạy test của module cụ thể
pytest tests/test_triage.py -v

# Chạy chỉ một test case
pytest tests/test_subdomain.py::TestSubdomainEnum::test_deduplication -v
```

---

## Ethical Guidelines

Tool này được thiết kế với ethical safeguards built-in:

**Scope enforcement** — Mọi request đều được check scope trước khi gửi. Tool sẽ từ chối và log warning nếu URL nằm ngoài scope đã config.

**Rate limiting** — Default 2 req/s per target. Tự động giảm khi detect target bị stress (response time tăng 3x hoặc nhận nhiều 429/503).

**Chỉ dùng trên authorized targets** — Chỉ scan target trong scope của chương trình bug bounty. Đọc kỹ program rules trước khi scan.

**Không aggressive scan** — Không chạy full port scan (`nmap -p-`) trên nhiều host cùng lúc. Nuclei exploit modules bị disable mặc định.

**Lưu permission documentation** — Lưu lại in-scope confirmation trước khi bắt đầu bất kỳ scan nào.

---

## Scan Metrics

Sau mỗi scan, tool in ra metrics để track performance:

```
──────────── Scan Metrics ────────────
Duration        : 8m 32s
Total requests  : 1,247
Req/minute      : 146
Findings        : 7 (2 High, 3 Medium, 2 Low)
False positives : 1 (filtered by AI)
FP rate         : 14.3%
Tools used      : subfinder, httpx, nuclei, dalfox
──────────────────────────────────────
```

---

## Roadmap

- [ ] Web UI dashboard (FastAPI + React) cho team hunting
- [ ] Integration với Burp Suite (export findings)
- [ ] GraphQL endpoint discovery module
- [ ] Mobile app recon (Android/iOS deeplinks)
- [ ] AI-powered JS deobfuscation
- [ ] Automatic PoC video recording

---

## Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11+ với asyncio |
| CLI | Click |
| Terminal UI | Rich |
| Database | SQLite |
| AI | Google Gemini API (gemini-1.5-flash) |
| Scheduler | APScheduler |
| PDF export | ReportLab + WeasyPrint |
| Testing | pytest + pytest-asyncio |
| Core tools | subfinder, amass, findomain, httpx, nuclei, dalfox, ffuf, naabu, subzy... |

---

## License

For educational and authorized security testing purposes only.  
The author is not responsible for misuse of this tool.

---

*Built by [PhucQuan] — Bug Hunter Team, HCMUTE ISC*
