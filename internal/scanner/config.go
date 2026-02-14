package scanner

import "time"

type Config struct {
	Concurrency int
	Timeout     time.Duration
	UserAgent   string
	MaxSnippet  int

	EnableRobots  bool
	EnableSitemap bool
	EnableCrawl   bool
	CrawlDepth    int
	CrawlLimit    int

	IndexChecker IndexChecker `json:"-"`
}
