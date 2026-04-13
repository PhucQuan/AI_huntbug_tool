# Changelog

## [2.0.0] - Major Update

### 🎉 Major Changes

#### AI Integration
- **Migrated from Claude to Gemini**: Thay đổi từ Anthropic Claude sang Google Gemini API
  - Miễn phí hơn cho personal use
  - Faster response times
  - Updated `core/ai/triage.py` và `core/ai/report_gen.py`
  - Updated `requirements.txt`: `anthropic` → `google-generativeai`

### ✨ New Features

#### Reconnaissance Modules

1. **Passive Subdomain Sources** (`core/recon/passive_sources.py`)
   - crt.sh (Certificate Transparency)
   - Wayback Machine (web.archive.org)
   - VirusTotal API
   - GitHub subdomain scraping (github-subdomains tool)
   - Tự động merge với active enumeration

2. **URL Collection Pipeline** (`core/recon/url_collection.py`)
   - **gau** (getallurls) - passive URL discovery
   - **katana** - active crawling với JS rendering
   - **hakrawler** - lightweight crawler
   - **urlfinder** - passive URL finder
   - Automatic filtering: params, sensitive files, JS files

3. **Parameter Discovery** (`core/recon/param_discovery.py`)
   - **arjun** - hidden parameter fuzzing
   - **gf patterns** - pattern-based URL filtering
     - XSS candidates
     - SQLi candidates
     - LFI candidates
     - SSRF candidates
     - Open Redirect candidates
     - IDOR candidates
   - Parameter extraction từ URLs

4. **JavaScript Analysis** (`core/recon/js_analysis.py`)
   - Extract API endpoints từ JS files
   - Secret detection (API keys, tokens, passwords, AWS keys, etc.)
   - Subdomain extraction từ JS
   - Comment analysis (sensitive info in comments)
   - Bulk analysis với concurrency

#### Vulnerability Scanning Modules

5. **Port Scanning** (`core/scan/port_scanner.py`)
   - **naabu** - fast port scanner
   - **nmap** - detailed service detection
   - **masscan** - ultra-fast scanning
   - Automatic service version detection

6. **SQL Injection Detection** (`core/scan/sqli_scanner.py`)
   - **sqlmap** integration - automated SQLi detection
   - Manual pattern-based detection
   - Technology-based URL filtering (PHP, ASP, JSP)
   - Error-based SQLi detection
   - Bulk scanning với rate limiting

7. **Subdomain Takeover** (`core/scan/takeover_scanner.py`)
   - **subzy** - automated takeover checker
   - Manual CNAME + fingerprint verification
   - Support 12+ services:
     - GitHub Pages, Heroku, Netlify, AWS S3
     - Shopify, Tumblr, WordPress.com, Ghost
     - Pantheon, Zendesk, Bitbucket, Azure

8. **.git Exposure Detection** (`core/scan/git_exposure.py`)
   - Automated .git directory detection
   - **git-dumper** integration - extract exposed repos
   - **GitTools** support
   - Sensitive file scanning trong dumped repos
   - Detect: .env, keys, credentials, configs

#### Enhanced Existing Modules

9. **Subdomain Enumeration** (Updated `core/recon/subdomain.py`)
   - Added **findomain** tool (4th active tool)
   - Integrated passive sources automatically
   - Improved error handling
   - Better progress reporting

### 🔧 Configuration

- Added `.env.example` với hướng dẫn setup API keys
- Support environment variables:
  - `GEMINI_API_KEY` (required for AI)
  - `VIRUSTOTAL_API_KEY` (optional)
  - `GITHUB_TOKEN` (optional)
  - `SLACK_WEBHOOK_URL` (optional)
  - `INTERACTSH_SERVER` (optional)

### 📚 Documentation

- **README.md**: Comprehensive documentation
  - Installation guide cho tất cả tools
  - Usage examples
  - Advanced workflows
  - API integration examples
- **CHANGELOG.md**: This file
- **.env.example**: Environment setup guide

### 🎯 Full Attack Surface Coverage

Project giờ cover đầy đủ theo bug bounty recon methodology:

#### Phase 1: Asset Discovery
- ✅ Subdomain enumeration (4 active tools + 4 passive sources)
- ✅ Alive host detection
- ✅ Technology fingerprinting
- ✅ Port scanning
- ✅ Screenshot capture

#### Phase 2: Content Discovery
- ✅ URL collection (active + passive)
- ✅ Directory fuzzing
- ✅ Parameter discovery
- ✅ JS file analysis
- ✅ Sensitive file detection

#### Phase 3: Vulnerability Detection
- ✅ Nuclei (3-phase smart scanning)
- ✅ XSS (dalfox)
- ✅ SQL Injection (sqlmap + manual)
- ✅ CORS misconfiguration
- ✅ SSRF
- ✅ Open Redirect
- ✅ CRLF Injection
- ✅ Subdomain Takeover
- ✅ .git Exposure

#### Phase 4: Intelligence & Reporting
- ✅ AI-powered triage (Gemini)
- ✅ False positive filtering
- ✅ Contextual severity scoring
- ✅ Attack chain suggestions
- ✅ HackerOne report generation
- ✅ Knowledge graph database

### 🚀 Performance Improvements

- Async/await throughout all modules
- Concurrent scanning với rate limiting
- Smart tool selection (fallbacks)
- Timeout handling
- Error recovery

### 🛡️ Safety Features

- Scope validation
- Rate limiting
- Stress detection
- Tool availability checking
- Graceful degradation

### 📊 Statistics

- **Total Modules**: 20+
- **Integrated Tools**: 30+
- **Vulnerability Types**: 15+
- **Lines of Code**: ~8000+

### 🔄 Migration Guide

#### From v1.x to v2.0

1. **Update dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Update API keys**:
   ```bash
   # Old
   ANTHROPIC_API_KEY=xxx
   
   # New
   GEMINI_API_KEY=xxx
   ```

3. **Install new tools** (see README.md):
   - findomain
   - gau, katana, hakrawler
   - naabu, subzy
   - git-dumper

4. **Code changes**:
   ```python
   # Old
   from core.ai.triage import AITriage
   triage = AITriage()  # Used Claude
   
   # New
   from core.ai.triage import AITriage
   triage = AITriage()  # Now uses Gemini
   # API tương thích, không cần thay đổi code
   ```

### 🐛 Bug Fixes

- Fixed subdomain deduplication
- Fixed async timeout issues
- Fixed JSON parsing errors
- Improved error messages

### 🎁 Coming Soon

- [ ] Integration với Burp Suite
- [ ] Slack/Discord notifications
- [ ] Web dashboard
- [ ] Docker support
- [ ] CI/CD integration
- [ ] Custom nuclei templates
- [ ] Machine learning for FP detection

---

**Full comparison với bài guide gốc: ✅ 100% coverage**
