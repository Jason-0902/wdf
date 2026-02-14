package scanner

import (
	"path/filepath"
	"strings"
)

func recommendedFix(path string, source DiscoverySource, a Analysis, flags analysisFlags, isSensitive bool) string {
	lp := strings.ToLower(path)

	if flags.DirectoryListing {
		return "Disable directory listings (autoindex) for this location and restrict access."
	}
	if flags.ConfirmedSecret {
		return "Rotate and revoke exposed secrets immediately, remove them from public responses, and restrict access."
	}
	if strings.HasPrefix(lp, "/.git") {
		return "Block access to VCS directories (e.g. /.git) at the web server and remove any exposed repository data."
	}
	if strings.HasPrefix(lp, "/.env") {
		return "Remove environment files from the web root and restrict access; rotate any exposed credentials."
	}
	ext := strings.ToLower(filepath.Ext(lp))
	switch ext {
	case ".zip", ".tar", ".gz", ".sql":
		return "Remove backup/dump artifacts from public paths and restrict access to internal storage."
	}
	if strings.Contains(lp, "phpinfo") {
		return "Remove phpinfo endpoints from production or restrict access to administrators only."
	}
	if strings.Contains(lp, "actuator") {
		return "Restrict Spring Boot actuator endpoints to authenticated/internal access and disable sensitive endpoints."
	}

	if source == SourceSitemap {
		return "If this content should not be indexed, remove it from the sitemap and restrict access."
	}
	if source == SourceRobots {
		return "Robots directives do not protect content; restrict access if sensitive and avoid listing sensitive paths in robots.txt."
	}
	if flags.NoIndex && a.Severity != SeverityHigh {
		return "Noindex is present; also restrict access if this content is sensitive."
	}
	if isSensitive && a.Severity != SeverityLow {
		return "Restrict access to this path (authentication/IP allowlist) and remove any sensitive content from public responses."
	}
	return ""
}

