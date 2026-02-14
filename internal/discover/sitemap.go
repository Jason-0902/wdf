package discover

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func FetchSitemaps(parent context.Context, client *http.Client, base *url.URL, seeds []string, userAgent string, timeout time.Duration, maxBytes int64, maxFetch int) ([]string, error) {
	if maxFetch <= 0 {
		maxFetch = 50
	}
	if maxBytes <= 0 {
		maxBytes = 2 << 20
	}

	seenSitemap := make(map[string]struct{}, len(seeds))
	queue := make([]string, 0, len(seeds))
	for _, s := range seeds {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seenSitemap[s]; ok {
			continue
		}
		seenSitemap[s] = struct{}{}
		queue = append(queue, s)
	}

	found := make([]string, 0, 1024)
	seenURL := make(map[string]struct{}, 1024)

	fetched := 0
	for len(queue) > 0 && fetched < maxFetch {
		su := queue[0]
		queue = queue[1:]
		fetched++

		ctx, cancel := context.WithTimeout(parent, timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, su, nil)
		if err != nil {
			cancel()
			continue
		}
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		req.Header.Set("Accept", "application/xml,text/xml,*/*")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}

		body := io.LimitReader(resp.Body, maxBytes)
		root, locs := parseSitemapXML(body)
		resp.Body.Close()
		cancel()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		if strings.EqualFold(root, "sitemapindex") {
			for _, loc := range locs {
				loc = strings.TrimSpace(loc)
				if loc == "" {
					continue
				}
				u, err := url.Parse(loc)
				if err != nil {
					continue
				}
				if u.Host != "" && !strings.EqualFold(u.Host, base.Host) {
					continue
				}
				if _, ok := seenSitemap[loc]; ok {
					continue
				}
				seenSitemap[loc] = struct{}{}
				queue = append(queue, loc)
			}
			continue
		}

		for _, loc := range locs {
			loc = strings.TrimSpace(loc)
			if loc == "" {
				continue
			}
			u, err := url.Parse(loc)
			if err != nil {
				continue
			}
			if u.Host != "" && !strings.EqualFold(u.Host, base.Host) {
				continue
			}
			u.Fragment = ""
			u.RawQuery = ""
			canon := u.String()
			if _, ok := seenURL[canon]; ok {
				continue
			}
			seenURL[canon] = struct{}{}
			found = append(found, canon)
		}
	}

	return found, nil
}

func parseSitemapXML(r io.Reader) (root string, locs []string) {
	dec := xml.NewDecoder(r)
	var inLoc bool
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if root == "" {
				root = t.Name.Local
			}
			if strings.EqualFold(t.Name.Local, "loc") {
				inLoc = true
				b.Reset()
			}
		case xml.CharData:
			if inLoc {
				b.Write([]byte(t))
			}
		case xml.EndElement:
			if inLoc && strings.EqualFold(t.Name.Local, "loc") {
				inLoc = false
				locs = append(locs, strings.TrimSpace(b.String()))
				b.Reset()
			}
		}
	}
	return root, locs
}

