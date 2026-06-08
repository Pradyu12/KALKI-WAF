package middleware

import (
	"io"
	"net/url"
	"strings"

	"github.com/Pradyu12/KALKI-WAF/proxy/internal/rules"
	"github.com/rs/zerolog/log"
)

type Inspector struct {
	engine *rules.Engine
	maxBodyBytes int64
}

func NewInspector(engine *rules.Engine, maxBodyBytes int64) *Inspector {
	if maxBodyBytes <= 0 {
		maxBodyBytes = 10 * 1024 * 1024
	}
	return &Inspector{
		engine:       engine,
		maxBodyBytes: maxBodyBytes,
	}
}

func (ins *Inspector) Process(ctx *Context) {
	score := 0.0
	var threats []string

	pathResults := ins.engine.Match(ctx.Request.URL.Path)
	score, threats = accumulate(score, threats, pathResults)

	queryResults := ins.engine.Match(ctx.Request.URL.RawQuery)
	score, threats = accumulate(score, threats, queryResults)

	for key, values := range ctx.Request.URL.Query() {
		for _, v := range values {
			decoded, err := url.QueryUnescape(v)
			if err == nil {
				qr := ins.engine.Match(decoded)
				score, threats = accumulate(score, threats, qr)
			}
			qr := ins.engine.Match(key + "=" + v)
			score, threats = accumulate(score, threats, qr)
		}
	}

	if ctx.Request.Body != nil {
		body, err := io.ReadAll(io.LimitReader(ctx.Request.Body, ins.maxBodyBytes))
		if err == nil {
			bodyStr := string(body)
			bodyResults := ins.engine.Match(bodyStr)
			score, threats = accumulate(score, threats, bodyResults)
		}
	}

	for key, values := range ctx.Request.Header {
		for _, v := range values {
			hr := ins.engine.Match(key + ": " + v)
			score, threats = accumulate(score, threats, hr)
		}
	}

	if len(threats) > 0 {
		ctx.ThreatScore = score
		ctx.ThreatType = strings.Join(threats, ",")
		ctx.Blocked = true
		log.Warn().Str("ip", clientIP(ctx.Request)).Str("threats", ctx.ThreatType).Float64("score", score).Msg("request blocked by inspector")
		httpError(ctx.Response, "Request blocked by WAF security rules")
	}
}

func accumulate(score float64, threats []string, results []rules.MatchResult) (float64, []string) {
	for _, r := range results {
		score += r.Score
		threats = append(threats, r.Category)
	}
	return score, threats
}
