package scanner

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"wdf/internal/discover"
)

type RequestResult struct {
	URL             string              `json:"url"`
	Method          string              `json:"method"`
	Path            string              `json:"path"`
	StatusCode      int                 `json:"status_code,omitempty"`
	Headers         map[string][]string `json:"headers,omitempty"`
	Snippet         string              `json:"snippet,omitempty"`
	Error           string              `json:"error,omitempty"`
	DurationMs      int64               `json:"duration_ms"`
	IndexedExposed  bool                `json:"indexed_exposed"`
	DiscoverySource DiscoverySource     `json:"discovery_source,omitempty"`
	RecommendedFix  string              `json:"recommended_fix,omitempty"`
	Analysis        Analysis            `json:"analysis"`
}

type Analysis struct {
	Severity    Severity `json:"severity"`
	Reasons     []string `json:"reasons,omitempty"`
	Patterns    []string `json:"matched_patterns,omitempty"`
	Interesting bool     `json:"interesting"`
}

type TargetResult struct {
	Target     string          `json:"target"`
	Normalized string          `json:"normalized"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	Results    []RequestResult `json:"results"`
}

type DiscoverySource string

const (
	SourceDictionary DiscoverySource = "dictionary"
	SourceRobots     DiscoverySource = "robots"
	SourceSitemap    DiscoverySource = "sitemap"
	SourceCrawler    DiscoverySource = "crawler"
)

type job struct {
	target     string
	baseURL    *url.URL
	path       string
	isSensitive bool
	critical    bool
	source      DiscoverySource
}

type jobResult struct {
	target string
	rr     RequestResult
}

func ScanTargets(ctx context.Context, targets []string, cfg Config, rs RuleSet) []TargetResult {
	started := time.Now().UTC()

	// Pre-normalize targets so we can error early and keep a stable output order.
	type tinfo struct {
		raw  string
		norm string
		u    *url.URL
		err  string
	}
	infos := make([]tinfo, 0, len(targets))
	for _, t := range targets {
		norm, u, err := normalizeTarget(t)
		ti := tinfo{raw: t, norm: norm, u: u}
		if err != nil {
			ti.err = err.Error()
		}
		infos = append(infos, ti)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].raw < infos[j].raw })

	// Prepare output shell in the same order.
	out := make([]TargetResult, 0, len(infos))
	idxByTarget := make(map[string]int, len(infos))
	for i, ti := range infos {
		tr := TargetResult{
			Target:     ti.raw,
			Normalized: ti.norm,
			StartedAt:  started,
		}
		if ti.err != "" {
			tr.FinishedAt = time.Now().UTC()
			tr.Results = append(tr.Results, RequestResult{
				URL:   ti.raw,
				Path: "",
				Error: ti.err,
				Analysis: Analysis{
					Severity:   SeverityLow,
					Reasons:    []string{"invalid target"},
					Interesting: false,
				},
			})
		}
		idxByTarget[ti.raw] = i
		out = append(out, tr)
	}

	jobs := make(chan job)
	results := make(chan jobResult, cfg.Concurrency*2)

	client := newHTTPClient(cfg)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for j := range jobs {
			rr := scanOne(ctx, client, cfg, rs, j.baseURL, j.path, j.isSensitive, j.critical, j.source)
			results <- jobResult{target: j.target, rr: rr}
		}
	}

	wg.Add(cfg.Concurrency)
	for i := 0; i < cfg.Concurrency; i++ {
		go worker()
	}

	go func() {
		// Close jobs first so workers can exit; then close results after all workers finish.
		for _, ti := range infos {
			if ti.err != "" {
				continue
			}

			pathPlans := buildPathPlan(ctx, client, cfg, rs, ti.u)
			for _, pp := range pathPlans {
				select {
				case <-ctx.Done():
					close(jobs)
					wg.Wait()
					close(results)
					return
				case jobs <- job{
					target:      ti.raw,
					baseURL:     ti.u,
					path:        pp.Path,
					isSensitive: pp.IsSensitive,
					critical:    pp.Critical,
					source:      pp.Source,
				}:
				}
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	// Aggregate.
	var mu sync.Mutex
	for jr := range results {
		mu.Lock()
		i := idxByTarget[jr.target]
		out[i].Results = append(out[i].Results, jr.rr)
		mu.Unlock()
	}

	// Finalize + stable sort per target.
	for i := range out {
		if out[i].FinishedAt.IsZero() {
			out[i].FinishedAt = time.Now().UTC()
		}
		sort.Slice(out[i].Results, func(a, b int) bool {
			if out[i].Results[a].Path == out[i].Results[b].Path {
				return out[i].Results[a].URL < out[i].Results[b].URL
			}
			return out[i].Results[a].Path < out[i].Results[b].Path
		})
	}

	return out
}

type pathPlan struct {
	Path       string
	IsSensitive bool
	Critical    bool
	Source      DiscoverySource
}

func buildPathPlan(ctx context.Context, client *http.Client, cfg Config, rs RuleSet, base *url.URL) []pathPlan {
	seen := make(map[string]pathPlan, len(rs.SensitivePathRules))

	add := func(p string, src DiscoverySource, isSensitive bool, critical bool) {
		n, ok := normalizePath(p)
		if !ok {
			return
		}
		if len(n) > 2048 {
			return
		}
		if prev, exists := seen[n]; exists {
			seen[n] = mergePlan(prev, pathPlan{Path: n, IsSensitive: prev.IsSensitive || isSensitive, Critical: prev.Critical || critical, Source: mergeSource(prev.Source, src)})
			return
		}
		seen[n] = pathPlan{Path: n, IsSensitive: isSensitive, Critical: critical, Source: src}
	}

	for _, r := range rs.SensitivePathRules {
		add(r.Path, SourceDictionary, true, r.Critical)
	}

	var robotSitemaps []string
	if cfg.EnableRobots {
		paths, sitemaps, _ := discover.FetchRobots(ctx, client, base, cfg.UserAgent, cfg.Timeout, 1<<20)
		robotSitemaps = sitemaps
		for _, p := range paths {
			add(p, SourceRobots, false, false)
		}
	}

	if cfg.EnableSitemap {
		sitemapSeeds := make([]string, 0, 1+len(robotSitemaps))
		sitemapSeeds = append(sitemapSeeds, resolvePath(base, "/sitemap.xml"))
		for _, s := range robotSitemaps {
			sitemapSeeds = append(sitemapSeeds, s)
		}
		urls, _ := discover.FetchSitemaps(ctx, client, base, sitemapSeeds, cfg.UserAgent, cfg.Timeout, 2<<20, 50)
		for _, u := range urls {
			if p, ok := normalizeURLToSameOriginPath(base, u); ok {
				add(p, SourceSitemap, false, false)
			}
		}
	}

	if cfg.EnableCrawl {
		depth := cfg.CrawlDepth
		if depth <= 0 {
			depth = 2
		}
		limit := cfg.CrawlLimit
		if limit <= 0 {
			limit = 20
		}
		urls, _ := discover.CrawlSameOrigin(ctx, client, base, cfg.UserAgent, cfg.Timeout, depth, limit, 256<<10)
		for _, u := range urls {
			if p, ok := normalizeURLToSameOriginPath(base, u); ok {
				add(p, SourceCrawler, false, false)
			}
		}
	}

	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	out := make([]pathPlan, 0, len(paths))
	for _, p := range paths {
		pp := seen[p]
		pp.Path = p
		out = append(out, pp)
	}
	return out
}

func mergeSource(prev, next DiscoverySource) DiscoverySource {
	if prev == "" {
		return next
	}
	if prev == SourceDictionary && next != "" && next != SourceDictionary {
		return next
	}
	return prev
}

func mergePlan(prev, next pathPlan) pathPlan {
	out := prev
	out.IsSensitive = prev.IsSensitive || next.IsSensitive
	out.Critical = prev.Critical || next.Critical
	out.Source = mergeSource(prev.Source, next.Source)
	return out
}

func normalizeTarget(raw string) (string, *url.URL, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil, &url.Error{Op: "parse", URL: raw, Err: errEmptyTarget{}}
	}
	if !strings.Contains(s, "://") {
		// Default to https if scheme is missing.
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return s, nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return s, nil, &url.Error{Op: "parse", URL: raw, Err: errUnsupportedScheme{scheme: u.Scheme}}
	}
	if u.Host == "" {
		return s, nil, &url.Error{Op: "parse", URL: raw, Err: errMissingHost{}}
	}
	u.Fragment = ""
	// Ensure a clean base path.
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), u, nil
}

type errEmptyTarget struct{}

func (e errEmptyTarget) Error() string { return "empty target" }

type errMissingHost struct{}

func (e errMissingHost) Error() string { return "missing host" }

type errUnsupportedScheme struct{ scheme string }

func (e errUnsupportedScheme) Error() string { return "unsupported scheme: " + e.scheme }
