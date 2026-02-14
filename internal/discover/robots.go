package discover

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func FetchRobots(parent context.Context, client *http.Client, base *url.URL, userAgent string, timeout time.Duration, maxBytes int64) ([]string, []string, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	robotsURL := (&url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/robots.txt"}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL, nil)
	if err != nil {
		return nil, nil, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	req.Header.Set("Accept", "text/plain,*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, nil
	}

	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	r := io.LimitReader(resp.Body, maxBytes)

	paths := make([]string, 0, 64)
	sitemaps := make([]string, 0, 4)
	seenP := make(map[string]struct{})
	seenS := make(map[string]struct{})

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}

		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "disallow:"):
			v := strings.TrimSpace(line[len("disallow:"):])
			if v == "" || v == "/" {
				continue
			}
			if strings.HasPrefix(v, "/") {
				if _, ok := seenP[v]; !ok {
					seenP[v] = struct{}{}
					paths = append(paths, v)
				}
			}
		case strings.HasPrefix(lower, "allow:"):
			v := strings.TrimSpace(line[len("allow:"):])
			if v == "" || v == "/" {
				continue
			}
			if strings.HasPrefix(v, "/") {
				if _, ok := seenP[v]; !ok {
					seenP[v] = struct{}{}
					paths = append(paths, v)
				}
			}
		case strings.HasPrefix(lower, "sitemap:"):
			v := strings.TrimSpace(line[len("sitemap:"):])
			if v == "" {
				continue
			}
			if _, ok := seenS[v]; !ok {
				seenS[v] = struct{}{}
				sitemaps = append(sitemaps, v)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	return paths, sitemaps, nil
}

