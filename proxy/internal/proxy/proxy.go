package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/Pradyu12/KALKI-WAF/proxy/internal/middleware"
	"github.com/Pradyu12/KALKI-WAF/proxy/internal/rules"
	"github.com/Pradyu12/KALKI-WAF/proxy/internal/telemetry"
	"github.com/rs/zerolog/log"
)

type ReverseProxy struct {
	target   *url.URL
	proxy    *httputil.ReverseProxy
	pipeline *middleware.Pipeline
	rules    *rules.Engine
	metrics  *telemetry.Metrics
}

func NewReverseProxy(upstream string, pipeline *middleware.Pipeline, ruleEngine *rules.Engine, m *telemetry.Metrics) *ReverseProxy {
	target, err := url.Parse(upstream)
	if err != nil {
		log.Fatal().Err(err).Str("url", upstream).Msg("invalid upstream URL")
	}

	rp := &ReverseProxy{
		target:   target,
		pipeline: pipeline,
		rules:    ruleEngine,
		metrics:  m,
	}

	rp.proxy = httputil.NewSingleHostReverseProxy(target)
	rp.proxy.ModifyResponse = rp.modifyResponse
	rp.proxy.ErrorHandler = rp.errorHandler

	return rp
}

func (rp *ReverseProxy) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rp.metrics.IncRequests()

		ctx := &middleware.Context{
			Request:     r,
			Response:    w,
			Blocked:     false,
			ThreatScore: 0,
			ThreatType:  "",
		}

		rp.pipeline.Execute(ctx)
		if ctx.Blocked {
			rp.metrics.IncBlocked(ctx.ThreatType)
			rp.metrics.ObserveLatency(time.Since(start))
			return
		}

		rp.proxy.ServeHTTP(w, r)
		rp.metrics.ObserveLatency(time.Since(start))
	})
}

func (rp *ReverseProxy) modifyResponse(resp *http.Response) error {
	resp.Header.Set("X-WAF", "KALKI")
	resp.Header.Set("X-WAF-Version", "2.0.0")
	return nil
}

func (rp *ReverseProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	rp.metrics.IncUpstreamTimeouts()
	http.Error(w, "Upstream unavailable", http.StatusBadGateway)
}
