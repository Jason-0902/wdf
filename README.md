# web-dork-fuzzer (wdf)

Defensive web exposure scanner for identifying potentially sensitive files/paths that may be discoverable by web crawlers and search engines.

Use only on systems you own or where you have explicit authorization.

## Build

```bash
go build -o wdf ./cmd/wdf
```

## Run

Single target:

```bash
./wdf -u https://example.com --concurrency 20 --timeout 10 --output results.json
```

List of targets (one per line, `#` comments allowed):

```bash
./wdf -l targets.txt --concurrency 50 --timeout 15 --output results.json
```

Optional discovery modules (disabled by default):

```bash
./wdf -u https://example.com --enable-robots --enable-sitemap --enable-crawl --crawl-depth 2 --crawl-limit 20
```

## Flags

- `-u string` target URL to scan
- `-l string` file with target URLs (one per line)
- `--concurrency int` max concurrent requests
- `--timeout int` per-request timeout (seconds)
- `--output string` output JSON path (default: stdout)
- `--enable-robots` discover paths from `robots.txt`
- `--enable-sitemap` discover URLs from `sitemap.xml` (and sitemap index)
- `--enable-crawl` discover same-origin links from HTML pages
- `--crawl-depth int` crawl depth (max 2)
- `--crawl-limit int` max pages fetched per target during crawling

## What It Scans

`wdf` checks a built-in dictionary of sensitive paths (e.g. `/.env`, `/.git/config`, `/backup.zip`, `/db.sql`, `/phpinfo.php`, `/swagger/index.html`, `/actuator/env`) and optionally augments that list using discovery modules.

Requests use `HEAD` when possible and fall back to `GET` to capture a small body snippet for analysis.

## Severity Logic (Summary)

- `200 OK` on a *critical* sensitive path: `high`
- `200 OK` on a *non-critical* sensitive path: `medium`
- Directory listing and confirmed secret patterns: always `high`
- If the response is explicitly `noindex` (`X-Robots-Tag` or `<meta name="robots">`), severity is downgraded by one level (never downgrades directory listings or confirmed secrets)

## Output

JSON report schema is backward compatible and extended with:

- `indexed_exposed` (bool)
- `discovery_source` (`dictionary|robots|sitemap|crawler`)
- `recommended_fix` (string)

Example (shape):

```json
{
  "generated_at": "2026-02-14T00:00:00Z",
  "config": { "concurrency": 20, "timeout": 10000000000 },
  "targets": [
    {
      "target": "https://example.com",
      "normalized": "https://example.com/",
      "results": [
        {
          "path": "/.env",
          "status_code": 200,
          "analysis": { "severity": "high" },
          "indexed_exposed": false,
          "discovery_source": "dictionary",
          "recommended_fix": "Remove environment files from the web root and restrict access; rotate any exposed credentials."
        }
      ]
    }
  ]
}
```

