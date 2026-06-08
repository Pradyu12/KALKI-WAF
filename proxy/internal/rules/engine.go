package rules

import (
	"regexp"
	"sync"

	"github.com/rs/zerolog/log"
)

type Engine struct {
	mu      sync.RWMutex
	rules   []Rule
	regexes map[string]*regexp.Regexp
	posture Posture
}

func NewEngine() *Engine {
	return &Engine{
		regexes: make(map[string]*regexp.Regexp),
		posture: PostureStandard,
	}
}

func (e *Engine) LoadDefaults() error {
	defaultRules := []Rule{
		{
			ID:          "sql-core-01",
			Name:        "SQLi Core Ruleset",
			Pattern:     `(?i)(\b(union|select|insert|update|delete|drop|alter|exec|execute)\b.*\b(from|into|set|where|table|database|values)\b|\b(or|and)\b\s*[\w\s]*[=<>])`,
			Severity:    "high",
			Category:    "sql_injection",
			Enabled:     true,
			Description: "Detects SQL injection attempts",
			Locations:   []string{"body", "query", "path"},
		},
		{
			ID:          "xss-scrutiny-01",
			Name:        "XSS Aggressive Scrutiny",
			Pattern:     `(?i)(<script[^>]*>|javascript\s*:|on\w+\s*=|alert\s*\(|prompt\s*\(|confirm\s*\()`,
			Severity:    "high",
			Category:    "xss",
			Enabled:     true,
			Description: "Detects cross-site scripting attempts",
			Locations:   []string{"body", "query"},
		},
		{
			ID:          "rfi-blocker-01",
			Name:        "Remote File Inclusion",
			Pattern:     `(?i)(file://|php://|ftp://|data://|expect://|ogg://)`,
			Severity:    "high",
			Category:    "rfi",
			Enabled:     true,
			Description: "Detects remote file inclusion attempts",
			Locations:   []string{"query", "body"},
		},
		{
			ID:          "cmdi-shield-01",
			Name:        "Command Injection Shield",
			Pattern:     `(?i)(;\s*(cat|ls|whoami|id|pwd|rm|chmod|wget|curl|bash|sh|python|perl|nc|netcat)\b|\|\s*(cat|ls|whoami|id|pwd|rm|chmod|wget|curl|bash|sh)\b|\$\s*\(|\`{2,}|` + "`" + `)`,
			Severity:    "high",
			Category:    "command_injection",
			Enabled:     true,
			Description: "Detects OS command injection attempts",
			Locations:   []string{"query", "body"},
		},
		{
			ID:          "path-traversal-01",
			Name:        "Path Traversal Protection",
			Pattern:     `(\.\./|\.\.\\)|(/etc/passwd|/etc/shadow|/windows/win.ini|/boot.ini)`,
			Severity:    "medium",
			Category:    "path_traversal",
			Enabled:     true,
			Description: "Detects path traversal attacks",
			Locations:   []string{"path", "query"},
		},
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, rule := range defaultRules {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			log.Warn().Err(err).Str("rule", rule.ID).Msg("failed to compile rule pattern")
			continue
		}
		e.rules = append(e.rules, rule)
		e.regexes[rule.ID] = re
	}

	log.Info().Int("count", len(e.rules)).Msg("default rules loaded")
	return nil
}

func (e *Engine) Match(data string) []MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.posture == PostureMonitor {
		return nil
	}

	var results []MatchResult
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		re := e.regexes[rule.ID]
		if re == nil {
			continue
		}
		if re.MatchString(data) {
			score := 1.0
			if rule.Severity == "high" {
				score = 2.0
			}
			results = append(results, MatchResult{
				RuleID:   rule.ID,
				Category: rule.Category,
				Severity: rule.Severity,
				Score:    score,
			})
		}
	}
	return results
}

func (e *Engine) SetPosture(p Posture) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.posture = p
	log.Info().Str("posture", string(p)).Msg("posture updated")
}
