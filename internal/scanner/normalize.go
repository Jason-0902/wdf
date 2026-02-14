package scanner

import (
	"net/url"
	"path"
	"strings"
)

func normalizePath(p string) (string, bool) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", false
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	cp := path.Clean(p)
	if cp == "." {
		cp = "/"
	}
	if !strings.HasPrefix(cp, "/") {
		cp = "/" + cp
	}
	return cp, true
}

func normalizeURLToSameOriginPath(base *url.URL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	// Same-origin only. A bare path has empty host and is allowed.
	if u.Host != "" && !strings.EqualFold(u.Host, base.Host) {
		return "", false
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	return normalizePath(p)
}

