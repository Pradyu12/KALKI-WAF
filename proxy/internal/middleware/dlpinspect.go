package middleware

import (
	"io"
	"regexp"
	"strings"
)

var dlpPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{name: "ssn", pattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{name: "email", pattern: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)},
	{name: "phone", pattern: regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`)},
	{name: "credit_card", pattern: regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)},
}

type DLP struct {
	enabled   bool
	maxSize int64
}

func NewDLP(enabled bool, maxSize int64) *DLP {
	if maxSize <= 0 {
		maxSize = 1024 * 1024
	}
	return &DLP{enabled: enabled, maxSize: maxSize}
}

func (d *DLP) Process(ctx *Context) {
	if !d.enabled || ctx.Request.Body == nil {
		return
	}
	body, err := io.ReadAll(io.LimitReader(ctx.Request.Body, d.maxSize))
	if err != nil {
		return
	}
	bodyStr := string(body)
	var found []string
	for _, dp := range dlpPatterns {
		if dp.pattern.MatchString(bodyStr) {
			found = append(found, dp.name)
		}
	}
	if len(found) > 0 {
		ctx.Blocked = true
		ctx.ThreatType = "dlp_" + strings.Join(found, "_")
		httpError(ctx.Response, "Request blocked by DLP policy")
	}
}
