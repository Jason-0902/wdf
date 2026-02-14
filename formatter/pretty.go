package formatter

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Jason-0902/wdf/internal/scanner"
	"github.com/Jason-0902/wdf/report"
)

func PrintPretty(rep report.Report, w io.Writer) {
	useColor := isTerminal(w)

	for _, t := range rep.Targets {
		printTargetHeader(w, useColor, t.Normalized)

		findings := filterFindings(t.Results)
		groups := groupBySeverity(findings)

		printGroup(w, useColor, scanner.SeverityHigh, groups[scanner.SeverityHigh])
		printGroup(w, useColor, scanner.SeverityMedium, groups[scanner.SeverityMedium])
		printGroup(w, useColor, scanner.SeverityLow, groups[scanner.SeverityLow])

		fmt.Fprintln(w, strings.Repeat("-", 60))
		printSummary(w, t, findings)
		fmt.Fprintln(w)
	}
}

func groupBySeverity(results []scanner.RequestResult) map[scanner.Severity][]scanner.RequestResult {
	out := map[scanner.Severity][]scanner.RequestResult{
		scanner.SeverityHigh:   nil,
		scanner.SeverityMedium: nil,
		scanner.SeverityLow:    nil,
	}
	for _, r := range results {
		out[r.Analysis.Severity] = append(out[r.Analysis.Severity], r)
	}
	for sev := range out {
		rs := out[sev]
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].Path == rs[j].Path {
				return rs[i].URL < rs[j].URL
			}
			return rs[i].Path < rs[j].Path
		})
		out[sev] = rs
	}
	return out
}

func printSummary(w io.Writer, t scanner.TargetResult, findings []scanner.RequestResult) {
	var high, med, low int
	for _, r := range findings {
		switch r.Analysis.Severity {
		case scanner.SeverityHigh:
			high++
		case scanner.SeverityMedium:
			med++
		default:
			low++
		}
	}

	dur := t.FinishedAt.Sub(t.StartedAt)
	if dur < 0 {
		dur = 0
	}

	fmt.Fprintln(w, "SUMMARY:")
	fmt.Fprintf(w, "  High: %d\n", high)
	fmt.Fprintf(w, "  Medium: %d\n", med)
	fmt.Fprintf(w, "  Low: %d\n", low)
	fmt.Fprintf(w, "  Total Findings: %d\n", len(findings))
	fmt.Fprintf(w, "  Scan Duration: %s\n", fmtDuration(dur))
}

func filterFindings(results []scanner.RequestResult) []scanner.RequestResult {
	out := make([]scanner.RequestResult, 0, len(results))
	for _, r := range results {
		if r.Analysis.Interesting {
			out = append(out, r)
		}
	}
	return out
}

func printTargetHeader(w io.Writer, useColor bool, target string) {
	h := fmt.Sprintf("SCAN TARGET: %s", target)
	if useColor {
		h = ansiBold + h + ansiReset
	}
	fmt.Fprintln(w, h)
	fmt.Fprintln(w, strings.Repeat("-", 60))
	fmt.Fprintln(w)
}

func printGroup(w io.Writer, useColor bool, sev scanner.Severity, results []scanner.RequestResult) {
	if len(results) == 0 {
		return
	}

	label := strings.ToUpper(string(sev))
	if useColor {
		label = colorForSeverity(sev) + label + ansiReset
	}
	fmt.Fprintf(w, "[%s]\n", label)

	const pathW = 30
	for _, r := range results {
		note := noteForResult(r)
		if tag := discoveryTag(r.DiscoverySource); tag != "" {
			note = strings.TrimSpace(note + " " + tag)
		}
		fmt.Fprintf(w, "  %-*s %-5d %s\n", pathW, r.Path, r.StatusCode, note)
	}
	fmt.Fprintln(w)
}

func noteForResult(r scanner.RequestResult) string {
	if r.Error != "" {
		return "Error: " + r.Error
	}
	if len(r.Analysis.Reasons) > 0 {
		// Prefer a concise, stable reason.
		return humanizeReason(r.Path, r.StatusCode, r.Analysis.Reasons[0])
	}
	return strings.TrimSpace(httpStatusText(r.StatusCode))
}

func humanizeReason(path string, status int, reason string) string {
	lp := strings.ToLower(path)
	lr := strings.ToLower(reason)

	switch {
	case status == 200 && strings.HasPrefix(lp, "/.env"):
		return "Sensitive config exposed"
	case status == 200 && strings.HasPrefix(lp, "/.git/"):
		return "Git metadata exposed"
	case status == 200 && (strings.Contains(lp, "swagger") || strings.Contains(lp, "openapi")):
		return "Public API documentation"
	case strings.Contains(lr, "directory listing"):
		return "Directory listing enabled"
	case strings.Contains(lr, "matched pattern"):
		return "Secret pattern detected"
	case strings.Contains(lr, "200 ok"):
		return "Sensitive content exposed"
	}
	return reason
}

func discoveryTag(src scanner.DiscoverySource) string {
	if src == "" {
		return ""
	}
	return "[" + string(src) + "]"
}

func httpStatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	default:
		if code == 0 {
			return ""
		}
		return fmt.Sprintf("HTTP %d", code)
	}
}

func fmtDuration(d time.Duration) string {
	sec := d.Seconds()
	if sec < 0 {
		sec = 0
	}
	if sec < 10 {
		return fmt.Sprintf("%.2fs", sec)
	}
	return fmt.Sprintf("%.1fs", sec)
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

func colorForSeverity(s scanner.Severity) string {
	switch s {
	case scanner.SeverityHigh:
		return ansiRed
	case scanner.SeverityMedium:
		return ansiYellow
	default:
		return ansiCyan
	}
}

