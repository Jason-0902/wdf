package scanner

import "regexp"

type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

type Pattern struct {
	Name     string
	Severity Severity
	Re       *regexp.Regexp
}

type SensitivePathRule struct {
	Path     string
	Critical bool
}

type RuleSet struct {
	SensitivePathRules []SensitivePathRule
	Patterns           []Pattern
}

func DefaultRuleSet() RuleSet {
	// Regexps must be compiled once and reused.
	return RuleSet{
		SensitivePathRules: append([]SensitivePathRule(nil), defaultSensitivePathRules...),
		Patterns:           append([]Pattern(nil), defaultPatterns...),
	}
}

var defaultSensitivePathRules = []SensitivePathRule{
	{Path: "/.env", Critical: true},
	{Path: "/.env.local", Critical: true},
	{Path: "/.env.dev", Critical: true},
	{Path: "/.env.prod", Critical: true},
	{Path: "/.git/config", Critical: true},
	{Path: "/.git/HEAD", Critical: false},
	{Path: "/.svn/entries", Critical: false},
	{Path: "/backup.zip", Critical: true},
	{Path: "/backup.tar", Critical: true},
	{Path: "/backup.tar.gz", Critical: true},
	{Path: "/db.sql", Critical: true},
	{Path: "/dump.sql", Critical: true},
	{Path: "/database.sql", Critical: true},
	{Path: "/phpinfo.php", Critical: false},
	{Path: "/swagger/index.html", Critical: false},
	{Path: "/swagger-ui.html", Critical: false},
	{Path: "/openapi.json", Critical: false},
	{Path: "/actuator/env", Critical: true},
	{Path: "/actuator/configprops", Critical: false},
	{Path: "/actuator/heapdump", Critical: true},
	{Path: "/actuator/beans", Critical: false},
	{Path: "/server-status", Critical: false},
	{Path: "/.DS_Store", Critical: false},
	{Path: "/.well-known/security.txt", Critical: false},
	{Path: "/sitemap.xml", Critical: false},
	{Path: "/robots.txt", Critical: false},
}

var defaultPatterns = []Pattern{
	{
		Name:     "Directory listing",
		Severity: SeverityHigh,
		Re:       regexp.MustCompile(`(?i)\bIndex of /`),
	},
	{
		Name:     "Password keyword",
		Severity: SeverityMedium,
		Re:       regexp.MustCompile(`(?i)\bpass(word|wd)?\b`),
	},
	{
		Name:     "Credentials keyword",
		Severity: SeverityMedium,
		Re:       regexp.MustCompile(`(?i)\bcredentials?\b`),
	},
	{
		Name:     "AWS access key id",
		Severity: SeverityHigh,
		Re:       regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	},
	{
		Name:     "AWS secret access key label",
		Severity: SeverityHigh,
		Re:       regexp.MustCompile(`(?i)\baws_secret_access_key\b`),
	},
	{
		Name:     "Google API key",
		Severity: SeverityHigh,
		Re:       regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
	},
	{
		Name:     "GitHub token",
		Severity: SeverityHigh,
		Re:       regexp.MustCompile(`\bgh[opsu]_[A-Za-z0-9]{36,}\b`),
	},
	{
		Name:     "Slack token",
		Severity: SeverityHigh,
		Re:       regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,48}\b`),
	},
	{
		Name:     "Stripe live secret key",
		Severity: SeverityHigh,
		Re:       regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{20,}\b`),
	},
	{
		Name:     "JWT token",
		Severity: SeverityHigh,
		Re:       regexp.MustCompile(`\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b`),
	},
	{
		Name:     "Private key header",
		Severity: SeverityHigh,
		Re:       regexp.MustCompile(`(?i)-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----`),
	},
	{
		Name:     "Database connection string",
		Severity: SeverityHigh,
		Re:       regexp.MustCompile(`(?i)\b(postgres(ql)?|mysql|mssql|mongodb(\+srv)?|redis)://[^\s"'<>]+`),
	},
	{
		Name:     "GCP service account marker",
		Severity: SeverityHigh,
		Re:       regexp.MustCompile(`(?i)"type"\s*:\s*"service_account"`),
	},
	{
		Name:     ".git keyword",
		Severity: SeverityMedium,
		Re:       regexp.MustCompile(`(?i)\.git`),
	},
	{
		Name:     "Generic api key label",
		Severity: SeverityMedium,
		Re:       regexp.MustCompile(`(?i)\bapi[_-]?key\b`),
	},
}
