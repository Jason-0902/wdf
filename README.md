# wdf (Web Dork Fuzzer)

wdf is a defensive security auditing tool written in Go for detecting exposure risks caused by accidentally public, crawlable, or search-indexed sensitive content on web applications.

In this context, "Google Dork exposure risk" means: endpoints and files that should not be publicly accessible (configuration files, VCS metadata, backups, admin/debug pages, API descriptions, etc.) can be discovered through normal web crawling and then surfaced by search engines via common search queries ("dorks"). wdf helps you assess whether a site is unintentionally serving this kind of content and how risky that exposure is.

wdf is designed for security auditing and exposure assessment. Use it only on systems you own or where you have explicit authorization.

## Key Features

- Sensitive path scanning: checks common high-risk paths such as `/.env`, `/.git/config`, backups (`.zip`, `.tar.gz`), dumps (`.sql`), `phpinfo.php`, Swagger/OpenAPI UIs, Spring Boot Actuator endpoints, and more
- Worker-pool based concurrent scanning: bounded parallel requests with configurable concurrency
- Timeout-safe HTTP client: request timeouts and safe redirect handling
- Robots.txt and sitemap discovery (optional): extracts `Allow`/`Disallow` paths and parses `sitemap.xml` (including sitemap indexes)
- Lightweight crawler (optional): same-origin HTML link discovery with bounded depth and page limits
- Secret pattern detection: content-based pattern matching for keys and tokens (e.g., AWS keys, private key headers, common tokens, connection strings)
- Indexability risk classification: structured severity labels (High / Medium / Low) with indexability signal hooks
- JSON reporting: machine-readable output suitable for pipelines and dashboards
- Pretty CLI output (optional): grouped, aligned, human-readable findings (like modern security tooling)

## How It Works (Architecture)

At a high level, wdf builds a target-specific scan plan, executes bounded HTTP requests, analyzes responses, and emits a JSON report.

- Dictionary-based exposure detection: a curated set of sensitive path rules (some marked critical)
- Discovery-based path expansion (optional): augment the dictionary with paths found in `robots.txt`, `sitemap.xml`, and limited crawling
- Content-based secret detection: scan small response snippets for high-signal patterns (keys/tokens/credentials)
- Risk classification engine: apply structured severity logic, optional indexability signal, and `noindex` downgrades where appropriate
- Reporting layer: produce a stable JSON report including remediation hints

Workflow diagram:

```text
Targets (-u/--url or -l/--list)
      |
      v
Normalize Targets
      |
      v
Build Path Plan
  |     |       |
  |     |       +--> (optional) Crawler discovery (same-origin, depth/limit)
  |     +----------> (optional) Sitemap discovery (sitemap.xml, sitemap index)
  +----------------> (optional) Robots discovery (Allow/Disallow + Sitemap links)
      |
      v
Deduplicate + Normalize Paths (per-target)
      |
      v
Worker Pool HTTP Requests (HEAD -> GET when needed)
      |
      v
Response Analysis
  - status + headers + snippet
  - secret patterns + directory listing checks
  - noindex detection
  - (optional) index checker signal
      |
      v
JSON Report (results + severity + recommendations)
```

## Installation

### Prerequisites

- Go 1.22+ recommended

### Install (Recommended)

Install the latest released version into your `GOBIN`/`GOPATH/bin`:

```bash
go install github.com/Jason-0902/wdf/cmd/wdf@latest
```

Verify:

```bash
wdf --version
```

### Build From Source

```bash
git clone https://github.com/Jason-0902/wdf.git
cd wdf
go build -o wdf ./cmd/wdf
```

## CLI Usage

### Help and Version

```bash
wdf --help
wdf --version
```

<<<<<<< HEAD
=======
### Output Modes

- Default behavior (no `--pretty`, no `--output`): JSON is written to stdout.
- `--output report.json`: JSON is written to the file (stdout can be used for human output via `--pretty`).
- `--pretty`: prints a grouped, human-readable report to stdout.

>>>>>>> bc85866 (Add pretty CLI output and improve formatter)
### Flags

- `-u, --url string`  
  Target URL to scan (e.g. `https://example.com`)

- `-l, --list string`  
  Path to file containing target URLs (one per line)

- `--concurrency int`  
  Maximum concurrent requests (worker pool size)

- `--timeout int`  
  Request timeout in seconds (per request)

- `--output string`  
  Write results JSON to this file (default: stdout)

- `--pretty`  
  Print a grouped, human-readable report to stdout (JSON still written to `--output` if set)

- `--enable-robots`  
  Enable `robots.txt` discovery (disabled by default)

- `--enable-sitemap`  
  Enable `sitemap.xml` discovery (disabled by default)

- `--enable-crawl`  
  Enable lightweight same-origin HTML discovery (disabled by default)

- `--crawl-depth int`  
  Crawl depth (max 2)

- `--crawl-limit int`  
  Maximum pages fetched per target during crawling

- `--version`  
  Print version and exit

- `-h, --help`  
  Print help and exit

### Examples

Scan a single host with strict timeouts:

```bash
wdf --url https://example.com --concurrency 10 --timeout 5 --output results.json
<<<<<<< HEAD
=======
```

Pretty output to stdout, JSON to a file:

```bash
wdf -u https://example.com --pretty --output results.json
>>>>>>> bc85866 (Add pretty CLI output and improve formatter)
```

Scan multiple targets and save output:

```bash
wdf --list targets.txt --concurrency 50 --timeout 15 --output wdf-report.json
```

Enable robots + sitemap only (no crawler):

```bash
wdf -u https://example.com --enable-robots --enable-sitemap --output results.json
```

Enable all discovery modules:

```bash
wdf -u https://example.com \
  --enable-robots \
  --enable-sitemap \
  --enable-crawl \
  --crawl-depth 2 \
  --crawl-limit 20 \
  --output results.json
```

## Example Output

### Pretty Output (Example)

```text
[+] Starting scan...
[+] Target: https://example.com
[+] Concurrency: 20
[+] Timeout: 10s

SCAN TARGET: https://example.com/
------------------------------------------------------------

[HIGH]
  /.env                          200   Sensitive config exposed [dictionary]

[MEDIUM]
  /swagger/index.html            200   Public API documentation [dictionary]

------------------------------------------------------------
SUMMARY:
  High: 1
  Medium: 1
  Low: 0
  Total Findings: 2
  Scan Duration: 3.42s

[+] Scan completed in 3.42 seconds
```

### JSON Output (Example)

wdf produces a single JSON report containing per-target results. Fields are stable and can be extended over time.

```json
{
  "generated_at": "2026-02-14T00:00:00Z",
  "config": {
    "concurrency": 20,
    "timeout": 10000000000,
    "user_agent": "wdf (defensive exposure scanner)",
    "max_snippet": 2048,
    "enable_robots": true,
    "enable_sitemap": true,
    "enable_crawl": false,
    "crawl_depth": 2,
    "crawl_limit": 20
  },
  "targets": [
    {
      "target": "https://example.com",
      "normalized": "https://example.com/",
      "started_at": "2026-02-14T00:00:00Z",
      "finished_at": "2026-02-14T00:00:02Z",
      "results": [
        {
          "url": "https://example.com/.env",
          "method": "GET",
          "path": "/.env",
          "status_code": 200,
          "duration_ms": 123,
          "indexed_exposed": false,
          "discovery_source": "dictionary",
          "recommended_fix": "Remove environment files from the web root and restrict access; rotate any exposed credentials.",
          "analysis": {
            "severity": "high",
            "interesting": true,
            "reasons": [
              "200 OK on critical sensitive path",
              "matched pattern: AWS access key id"
            ],
            "matched_patterns": [
              "AWS access key id"
            ]
          }
        }
      ]
    }
  ]
}
```

## Risk Classification Logic

wdf classifies results as High, Medium, or Low based on structured rules and response analysis.

### High

- `200 OK` on a critical sensitive path (e.g. credential/config artifacts, VCS configs, heap dumps)
- Directory listings detected (e.g. "Index of /" patterns and heuristics)
- Confirmed secret/token patterns detected in content snippets (e.g. access keys, private key headers, high-signal tokens)
- Marked as indexed exposure (`indexed_exposed: true`) by an indexability checker (interface is present for future integrations)

### Medium

- `200 OK` on a non-critical sensitive path (exposure present, but typically lower impact than confirmed secrets/critical artifacts)
- Other suspicious signals that do not meet high-confidence secret/directory listing criteria

### Low

- Non-sensitive paths with benign responses
- Sensitive paths that do not return risky content (e.g. 404/403) and do not match secret/directory listing patterns

### Indexability and `noindex`

- If an indexability checker reports the content is indexed, severity is raised to High and `indexed_exposed` is set to `true`.
- If content is explicitly marked `noindex` (via `X-Robots-Tag: noindex/none` or `<meta name=\"robots\" content=\"noindex\">`), severity is downgraded by one level, but never downgraded for:
  - directory listings
  - confirmed secret pattern matches

## Security Philosophy

- wdf does not exploit vulnerabilities and does not attempt to gain access.
- It focuses on detecting exposed content that is already publicly reachable.
- It is intended for defensive security posture assessment: hardening, exposure reduction, and audit workflows.
- If you discover exposure on systems you do not own, follow responsible disclosure practices and obtain authorization before any testing.

## Roadmap

- Search engine API integrations (via official APIs)
  - Google Custom Search API
  - Bing Web Search API
- Continuous monitoring mode (scheduled scans, diffing, alerting)
- CI/CD integration patterns (fail builds on High severity findings)
- Optional dashboard UI for reporting and trend analysis

## License

MIT License. See `LICENSE`.
<<<<<<< HEAD

=======
>>>>>>> bc85866 (Add pretty CLI output and improve formatter)
