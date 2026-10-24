package mitm

import (
	"net/netip"
	"strings"
)

// Rewrite is a declarative module rewrite rule.
type Rewrite struct {
	// Phase: url / header / body / request-header / response-header / request-body / response-body
	Phase   string `json:"phase"`
	Pattern string `json:"pattern"`
	Target  string `json:"target"`
	Flag    string `json:"flag"`
	Search  string `json:"search"`
	Name    string `json:"name"`
	Value   string `json:"value"`
}

// Script is a module script (Surge script phase, pattern and source).
type Script struct {
	// Phase: http-request / http-response
	Phase    string `json:"phase"`
	Pattern  string `json:"pattern"`
	Content  string `json:"content"`
	Argument string `json:"argument"`
	Engine   string `json:"engine"`
}

// CronScript is a scheduled (cron) script executed by the in-process scheduler.
type CronScript struct {
	Name     string `json:"name"`
	Schedule string `json:"schedule"` // 5-field cron: min hour day month weekday
	Content  string `json:"content"`
	Argument string `json:"argument"`
	Enabled  bool   `json:"enabled"`
}

// JqRule is a Surge [Body Rewrite] jq expression.
type JqRule struct {
	// Phase: http-request-jq / http-response-jq
	Phase   string `json:"phase"`
	Pattern string `json:"pattern"`
	Expr    string `json:"expr"`
}

// HTTPRule is a module URL-REGEX/USER-AGENT rule evaluated at the MITM HTTP layer.
type HTTPRule struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
	Policy  string `json:"policy"`
}

// LocalResponse is a Surge [Map Local] rule: return a fixed local response.
type LocalResponse struct {
	Pattern string   `json:"pattern"`
	Data    string   `json:"data"`
	Status  int      `json:"status"`
	Headers []string `json:"headers"`
}

// RulesFile is stored outside the main config to keep the YAML/IPC payload small.
type RulesFile struct {
	Rewrites       []Rewrite       `json:"rewrites"`
	Scripts        []Script        `json:"scripts"`
	JqRules        []JqRule        `json:"bodyJq"`
	LocalResponses []LocalResponse `json:"locals"`
	HTTPRules      []HTTPRule      `json:"httpRules"`
}

// Config is the runtime configuration of the built-in TLS interception layer.
type Config struct {
	Enable         bool
	Domains        []string
	ExcludeDomains []string
	CaptureBody    bool
	MaxBodySize    int
	Rewrites       []Rewrite
	Scripts        []Script
	JqRules        []JqRule
	LocalResponses []LocalResponse
	HTTPRules      []HTTPRule
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.TrimPrefix(domain, ".")
	return domain
}

func matchDomain(host string, pattern string) bool {
	host = normalizeDomain(host)
	pattern = normalizeDomain(pattern)
	if host == "" || pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // keep leading dot
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(host, pattern[1:])
	}
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

// Match reports whether the host should be intercepted.
func (c *Config) Match(host string) bool {
	if c == nil || !c.Enable {
		return false
	}
	for _, pattern := range c.ExcludeDomains {
		if matchDomain(host, pattern) {
			return false
		}
	}
	if len(c.Domains) == 0 {
		return false
	}
	for _, pattern := range c.Domains {
		if matchDomain(host, pattern) {
			return true
		}
	}
	return false
}

// MatchAddr is a helper for metadata that carries an IP instead of a domain.
func MatchAddr(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsValid()
}
