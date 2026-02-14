package discover

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var linkAttrRe = regexp.MustCompile(`(?is)\b(?:href|src)\s*=\s*(?:"([^"]+)"|'([^']+)')`)

func CrawlSameOrigin(parent context.Context, client *http.Client, base *url.URL, userAgent string, timeout time.Duration, maxDepth int, maxPages int, maxBytes int64) ([]string, error) {
	if maxDepth <= 0 {
		maxDepth = 2
	}
	if maxDepth > 2 {
		maxDepth = 2
	}
	if maxPages <= 0 {
		maxPages = 20
	}
	if maxBytes <= 0 {
		maxBytes = 256 << 10
	}

	type item struct {
		u     *url.URL
		depth int
	}

	start := &url.URL{Scheme: base.Scheme, Host: base.Host, Path: base.Path}
	start.Fragment = ""
	start.RawQuery = ""

	visited := make(map[string]struct{}, maxPages)
	discovered := make(map[string]struct{}, maxPages*3)

	queue := make([]item, 0, maxPages)
	queue = append(queue, item{u: start, depth: 0})

	for len(queue) > 0 && len(visited) < maxPages {
		it := queue[0]
		queue = queue[1:]

		canon := canonicalURL(it.u)
		if _, ok := visited[canon]; ok {
			continue
		}
		visited[canon] = struct{}{}
		discovered[canon] = struct{}{}

		ctx, cancel := context.WithTimeout(parent, timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, canon, nil)
		if err != nil {
			cancel()
			continue
		}
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}

		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if resp.StatusCode != http.StatusOK || !strings.Contains(ct, "html") {
			resp.Body.Close()
			cancel()
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
		resp.Body.Close()
		cancel()

		links := extractLinks(string(body))
		for _, l := range links {
			u, ok := resolveSameOrigin(it.u, base, l)
			if !ok {
				continue
			}
			cu := canonicalURL(u)
			discovered[cu] = struct{}{}
			if it.depth+1 <= maxDepth {
				if _, ok := visited[cu]; !ok {
					queue = append(queue, item{u: u, depth: it.depth + 1})
				}
			}
		}
	}

	out := make([]string, 0, len(discovered))
	for u := range discovered {
		out = append(out, u)
	}
	return out, nil
}

func extractLinks(html string) []string {
	matches := linkAttrRe.FindAllStringSubmatch(html, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		var v string
		if len(m) > 1 && m[1] != "" {
			v = m[1]
		} else if len(m) > 2 && m[2] != "" {
			v = m[2]
		}
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		low := strings.ToLower(v)
		if strings.HasPrefix(low, "mailto:") || strings.HasPrefix(low, "javascript:") || strings.HasPrefix(low, "data:") || strings.HasPrefix(low, "tel:") {
			continue
		}
		out = append(out, v)
	}
	return out
}

func resolveSameOrigin(basePage *url.URL, origin *url.URL, raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, false
	}
	if u.Scheme == "" && u.Host == "" {
		u = basePage.ResolveReference(u)
	}
	u.Fragment = ""
	u.RawQuery = ""
	if u.Scheme != "" && u.Scheme != origin.Scheme {
		return nil, false
	}
	if u.Host != "" && !strings.EqualFold(u.Host, origin.Host) {
		return nil, false
	}
	if u.Scheme == "" {
		u.Scheme = origin.Scheme
	}
	if u.Host == "" {
		u.Host = origin.Host
	}
	return u, true
}

func canonicalURL(u *url.URL) string {
	c := *u
	c.Fragment = ""
	c.RawQuery = ""
	if c.Path == "" {
		c.Path = "/"
	}
	return c.String()
}

