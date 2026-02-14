package scanner

import (
	"net/http"
	"regexp"
	"strings"
)

var (
	metaRobotsRe = regexp.MustCompile(`(?is)<meta[^>]+name\s*=\s*["']robots["'][^>]*>`)
	contentAttr  = regexp.MustCompile(`(?is)\bcontent\s*=\s*["']([^"']+)["']`)
)

type analysisFlags struct {
	NoIndex         bool
	DirectoryListing bool
	ConfirmedSecret bool
}

func analyze(path string, status int, headers map[string][]string, snippet string, rs RuleSet, isSensitive bool, critical bool) (Analysis, analysisFlags) {
	var a Analysis
	a.Severity = SeverityLow
	a.Interesting = false

	var flags analysisFlags
	var reasons []string
	var matched []string

	if isSensitive && status == http.StatusOK {
		if critical {
			a.Severity = SeverityHigh
			reasons = append(reasons, "200 OK on critical sensitive path")
		} else {
			a.Severity = SeverityMedium
			reasons = append(reasons, "200 OK on sensitive path")
		}
		a.Interesting = true
	}

	if snippet != "" {
		for _, p := range rs.Patterns {
			if p.Re != nil && p.Re.MatchString(snippet) {
				matched = append(matched, p.Name)
				reasons = append(reasons, "matched pattern: "+p.Name)
				a.Interesting = true

				if p.Name == "Directory listing" {
					flags.DirectoryListing = true
				}
				if p.Severity == SeverityHigh && p.Name != "Directory listing" {
					flags.ConfirmedSecret = true
				}

				if severityRank(p.Severity) > severityRank(a.Severity) {
					a.Severity = p.Severity
				}
			}
		}
	}

	// Keep this heuristic even if the regex doesn't match due to snippet truncation.
	if containsIndexOf(snippet) {
		flags.DirectoryListing = true
		a.Interesting = true
		reasons = append(reasons, "directory listing detected")
		if a.Severity != SeverityHigh {
			a.Severity = SeverityHigh
		}
	}

	if headers != nil {
		if v := firstHeader(headers, "Content-Disposition"); v != "" && strings.Contains(strings.ToLower(v), "attachment") {
			if a.Severity == SeverityLow {
				a.Severity = SeverityMedium
			}
			a.Interesting = true
			reasons = append(reasons, "downloadable attachment response")
		}
		if x := firstHeader(headers, "X-Robots-Tag"); hasNoIndexDirective(x) {
			flags.NoIndex = true
			reasons = append(reasons, "X-Robots-Tag indicates noindex")
		}
	}

	if hasMetaNoIndex(snippet) {
		flags.NoIndex = true
		reasons = append(reasons, "meta robots indicates noindex")
	}

	// Downgrade one level if explicitly noindex, but never downgrade confirmed secrets or directory listing.
	if flags.NoIndex && !flags.ConfirmedSecret && !flags.DirectoryListing {
		switch a.Severity {
		case SeverityHigh:
			a.Severity = SeverityMedium
			reasons = append(reasons, "severity downgraded due to explicit noindex")
		case SeverityMedium:
			a.Severity = SeverityLow
			reasons = append(reasons, "severity downgraded due to explicit noindex")
		}
	}

	a.Reasons = dedupeStrings(reasons)
	a.Patterns = dedupeStrings(matched)
	return a, flags
}

func containsIndexOf(s string) bool {
	return strings.Contains(strings.ToLower(s), "index of /")
}

func hasNoIndexDirective(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return false
	}
	// RFC-style directives: noindex, none, etc.
	parts := strings.Split(v, ",")
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t == "noindex" || t == "none" {
			return true
		}
	}
	return false
}

func hasMetaNoIndex(html string) bool {
	if html == "" {
		return false
	}
	m := metaRobotsRe.FindString(html)
	if m == "" {
		return false
	}
	cm := contentAttr.FindStringSubmatch(m)
	if len(cm) < 2 {
		return false
	}
	return hasNoIndexDirective(cm[1])
}

func firstHeader(h map[string][]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func severityRank(s Severity) int {
	switch s {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	default:
		return 1
	}
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

