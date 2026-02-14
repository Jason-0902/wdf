package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"wdf/internal/scanner"
	"wdf/report"
)

func main() {
	var (
		targetURL   = flag.String("u", "", "target URL to scan (e.g. https://example.com)")
		listPath    = flag.String("l", "", "path to file containing list of target URLs (one per line)")
		concurrency = flag.Int("concurrency", 20, "max concurrent requests")
		timeoutSec  = flag.Int("timeout", 10, "request timeout in seconds")
		outputPath  = flag.String("output", "", "write results JSON to this file (default: stdout)")

		enableRobots  = flag.Bool("enable-robots", false, "enable robots.txt discovery (disabled by default)")
		enableSitemap = flag.Bool("enable-sitemap", false, "enable sitemap.xml discovery (disabled by default)")
		enableCrawl   = flag.Bool("enable-crawl", false, "enable lightweight same-origin HTML discovery (disabled by default)")
		crawlDepth    = flag.Int("crawl-depth", 2, "crawler depth (max 2)")
		crawlLimit    = flag.Int("crawl-limit", 20, "max pages fetched per target during crawling")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "wdf: web-dork-fuzzer (defensive exposure scanner)\n\n")
		fmt.Fprintf(os.Stderr, "Use only on systems you own or where you have explicit authorization.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *targetURL == "" && *listPath == "" {
		fmt.Fprintln(os.Stderr, "error: must provide -u or -l")
		os.Exit(2)
	}
	if *targetURL != "" && *listPath != "" {
		fmt.Fprintln(os.Stderr, "error: provide only one of -u or -l")
		os.Exit(2)
	}
	if *concurrency <= 0 {
		fmt.Fprintln(os.Stderr, "error: --concurrency must be > 0")
		os.Exit(2)
	}
	if *timeoutSec <= 0 {
		fmt.Fprintln(os.Stderr, "error: --timeout must be > 0")
		os.Exit(2)
	}
	if *crawlDepth < 0 {
		fmt.Fprintln(os.Stderr, "error: --crawl-depth must be >= 0")
		os.Exit(2)
	}
	if *crawlLimit < 0 {
		fmt.Fprintln(os.Stderr, "error: --crawl-limit must be >= 0")
		os.Exit(2)
	}

	targets, err := loadTargets(*targetURL, *listPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "error: no targets to scan")
		os.Exit(2)
	}

	cfg := scanner.Config{
		Concurrency: *concurrency,
		Timeout:     time.Duration(*timeoutSec) * time.Second,
		UserAgent:   "web-dork-fuzzer (defensive scanner)",
		MaxSnippet:  2048,

		EnableRobots:  *enableRobots,
		EnableSitemap: *enableSitemap,
		EnableCrawl:   *enableCrawl,
		CrawlDepth:    minInt(*crawlDepth, 2),
		CrawlLimit:    *crawlLimit,
	}

	ctx := context.Background()
	rep := report.Report{
		GeneratedAt: time.Now().UTC(),
		Config:      cfg,
	}

	rs := scanner.DefaultRuleSet()
	results := scanner.ScanTargets(ctx, targets, cfg, rs)
	rep.Targets = results

	var out *os.File
	if *outputPath == "" {
		out = os.Stdout
	} else {
		f, err := os.Create(*outputPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	if err := report.WriteJSON(out, rep); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func loadTargets(single, listPath string) ([]string, error) {
	uniq := make(map[string]struct{})
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return
		}
		uniq[s] = struct{}{}
	}

	if single != "" {
		add(single)
	} else {
		f, err := os.Open(listPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}

	targets := make([]string, 0, len(uniq))
	for t := range uniq {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	return targets, nil
}
