package scanner

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

func newHTTPClient(cfg Config) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxConnsPerHost:       0,
		MaxIdleConnsPerHost:   10,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func scanOne(parent context.Context, client *http.Client, cfg Config, rs RuleSet, base *url.URL, path string, isSensitive bool, critical bool, source DiscoverySource) RequestResult {
	start := time.Now()
	full := resolvePath(base, path)

	rr := RequestResult{
		URL:             full,
		Path:            path,
		Method:          "HEAD",
		DiscoverySource: source,
		Analysis: Analysis{
			Severity:   SeverityLow,
			Interesting: false,
		},
	}

	ctx, cancel := context.WithTimeout(parent, cfg.Timeout)
	defer cancel()

	// Prefer HEAD to reduce transfer; fall back to GET when HEAD is unsupported or we need body for analysis.
	status, hdr, body, usedMethod, err := doRequest(ctx, client, cfg, full)
	rr.Method = usedMethod
	rr.StatusCode = status
	rr.Headers = hdr
	rr.Snippet = body
	if err != nil {
		rr.Error = err.Error()
	}

	a, flags := analyze(path, status, hdr, body, rs, isSensitive, critical)

	// Optional indexability module (stubbed by default).
	if cfg.IndexChecker != nil {
		target := base.Scheme + "://" + base.Host
		indexed, ierr := cfg.IndexChecker.IsIndexed(ctx, target, path)
		if ierr == nil && indexed {
			rr.IndexedExposed = true
			if a.Severity != SeverityHigh {
				a.Severity = SeverityHigh
			}
			a.Interesting = true
			a.Reasons = append(a.Reasons, "indexed in search engine")
		} else if ierr != nil {
			// Keep errors non-fatal; record as a low-signal reason.
			a.Reasons = append(a.Reasons, "index check error: "+ierr.Error())
		}
	}

	a.Reasons = dedupeStrings(a.Reasons)
	rr.Analysis = a
	rr.RecommendedFix = recommendedFix(path, source, a, flags, isSensitive)
	rr.DurationMs = time.Since(start).Milliseconds()
	return rr
}

func doRequest(ctx context.Context, client *http.Client, cfg Config, fullURL string) (status int, headers map[string][]string, snippet string, method string, err error) {
	// Attempt HEAD first.
	status, headers, _, err = do(ctx, client, cfg, fullURL, http.MethodHead)
	if err == nil && status != http.StatusMethodNotAllowed && status != http.StatusNotImplemented {
		// HEAD success; decide whether we need body.
		if status == http.StatusOK {
			// GET for a snippet to run keyword checks.
			status, headers, snippet, err = do(ctx, client, cfg, fullURL, http.MethodGet)
			return status, headers, snippet, http.MethodGet, err
		}
		return status, headers, "", http.MethodHead, nil
	}

	// Fall back to GET.
	status, headers, snippet, err = do(ctx, client, cfg, fullURL, http.MethodGet)
	return status, headers, snippet, http.MethodGet, err
}

func do(ctx context.Context, client *http.Client, cfg Config, fullURL string, method string) (status int, headers map[string][]string, snippet string, err error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return 0, nil, "", err
	}
	if cfg.UserAgent != "" {
		req.Header.Set("User-Agent", cfg.UserAgent)
	}
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()

	hdr := make(map[string][]string, len(resp.Header))
	for k, v := range resp.Header {
		cp := make([]string, len(v))
		copy(cp, v)
		hdr[k] = cp
	}

	if method == http.MethodHead {
		return resp.StatusCode, hdr, "", nil
	}

	max := cfg.MaxSnippet
	if max <= 0 {
		max = 2048
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, int64(max)))
	snippet = sanitizeSnippet(b, resp.Header.Get("Content-Type"))
	return resp.StatusCode, hdr, snippet, nil
}

func sanitizeSnippet(b []byte, contentType string) string {
	if len(b) == 0 {
		return ""
	}

	// If it looks like text or json/xml/html, attempt to keep it readable.
	ct := strings.ToLower(contentType)
	isTexty := strings.HasPrefix(ct, "text/") || strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "html")

	if !isTexty && !utf8.Valid(b) {
		// For binary-ish data, avoid spewing random bytes; return a small safe marker.
		return "[non-text content]"
	}

	b = bytes.ToValidUTF8(b, []byte("?"))
	// Replace most control chars except whitespace.
	out := make([]byte, 0, len(b))
	for _, r := range string(b) {
		if r == '\n' || r == '\r' || r == '\t' {
			out = append(out, byte(r))
			continue
		}
		if r < 32 || r == 127 {
			out = append(out, '.')
			continue
		}
		if r > 0x10FFFF {
			out = append(out, '?')
			continue
		}
		out = append(out, []byte(string(r))...)
	}
	return string(out)
}

func resolvePath(base *url.URL, p string) string {
	u := *base
	ref := &url.URL{Path: p}
	return u.ResolveReference(ref).String()
}
