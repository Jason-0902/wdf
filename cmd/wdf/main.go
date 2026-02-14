package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Jason-0902/wdf/internal/scanner"
	"github.com/Jason-0902/wdf/report"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wdf", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		targetURL string
		listPath  string
		output    string

		concurrency int
		timeoutSec  int

		enableRobots  bool
		enableSitemap bool
		enableCrawl   bool
		crawlDepth    int
		crawlLimit    int

		showVersion bool
		showHelp    bool
	)

	fs.StringVar(&targetURL, "u", "", "target URL to scan (e.g. https://example.com)")
	fs.StringVar(&targetURL, "url", "", "target URL to scan (e.g. https://example.com)")
	fs.StringVar(&listPath, "l", "", "path to file containing list of target URLs (one per line)")
	fs.StringVar(&listPath, "list", "", "path to file containing list of target URLs (one per line)")
	fs.IntVar(&concurrency, "concurrency", 20, "max concurrent requests")
	fs.IntVar(&timeoutSec, "timeout", 10, "request timeout in seconds")
	fs.StringVar(&output, "output", "", "write results JSON to this file (default: stdout)")

	fs.BoolVar(&enableRobots, "enable-robots", false, "enable robots.txt discovery (disabled by default)")
	fs.BoolVar(&enableSitemap, "enable-sitemap", false, "enable sitemap.xml discovery (disabled by default)")
	fs.BoolVar(&enableCrawl, "enable-crawl", false, "enable lightweight same-origin HTML discovery (disabled by default)")
	fs.IntVar(&crawlDepth, "crawl-depth", 2, "crawler depth (max 2)")
	fs.IntVar(&crawlLimit, "crawl-limit", 20, "max pages fetched per target during crawling")

	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.BoolVar(&showHelp, "h", false, "show help")
	fs.BoolVar(&showHelp, "help", false, "show help")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "wdf (Web Dork Fuzzer)\n")
		fmt.Fprintf(stderr, "Defensive exposure scanner for crawlable and search-indexed sensitive web content.\n\n")
		fmt.Fprintf(stderr, "Usage:\n")
		fmt.Fprintf(stderr, "  wdf -u https://example.com [flags]\n")
		fmt.Fprintf(stderr, "  wdf -l targets.txt [flags]\n\n")
		fmt.Fprintf(stderr, "Examples:\n")
		fmt.Fprintf(stderr, "  wdf -u https://example.com --concurrency 20 --timeout 10 --output results.json\n")
		fmt.Fprintf(stderr, "  wdf -l targets.txt --enable-robots --enable-sitemap\n")
		fmt.Fprintf(stderr, "  wdf --version\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n\n", err)
		fs.Usage()
		return 2
	}

	if showHelp {
		fs.Usage()
		return 0
	}
	if showVersion {
		fmt.Fprintf(stdout, "wdf %s\n", version)
		return 0
	}

	if targetURL == "" && listPath == "" {
		fmt.Fprintln(stderr, "error: must provide -u/--url or -l/--list")
		fmt.Fprintln(stderr)
		fs.Usage()
		return 2
	}
	if targetURL != "" && listPath != "" {
		fmt.Fprintln(stderr, "error: provide only one of -u/--url or -l/--list")
		fmt.Fprintln(stderr)
		fs.Usage()
		return 2
	}
	if concurrency <= 0 {
		fmt.Fprintln(stderr, "error: --concurrency must be > 0")
		return 2
	}
	if timeoutSec <= 0 {
		fmt.Fprintln(stderr, "error: --timeout must be > 0")
		return 2
	}
	if crawlDepth < 0 {
		fmt.Fprintln(stderr, "error: --crawl-depth must be >= 0")
		return 2
	}
	if crawlLimit < 0 {
		fmt.Fprintln(stderr, "error: --crawl-limit must be >= 0")
		return 2
	}

	targets, err := loadTargets(targetURL, listPath)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if len(targets) == 0 {
		fmt.Fprintln(stderr, "error: no targets to scan")
		return 2
	}

	cfg := scanner.Config{
		Concurrency: concurrency,
		Timeout:     time.Duration(timeoutSec) * time.Second,
		UserAgent:   "wdf (defensive exposure scanner)",
		MaxSnippet:  2048,

		EnableRobots:  enableRobots,
		EnableSitemap: enableSitemap,
		EnableCrawl:   enableCrawl,
		CrawlDepth:    clampInt(crawlDepth, 0, 2),
		CrawlLimit:    crawlLimit,
	}

	ctx := context.Background()
	rep := report.Report{
		GeneratedAt: time.Now().UTC(),
		Config:      cfg,
	}

	rs := scanner.DefaultRuleSet()
	rep.Targets = scanner.ScanTargets(ctx, targets, cfg, rs)

	var out io.Writer = stdout
	var f *os.File
	if output != "" {
		ff, err := os.Create(output)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		f = ff
		defer f.Close()
		out = f
	}

	if err := report.WriteJSON(out, rep); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
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

