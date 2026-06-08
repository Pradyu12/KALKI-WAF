package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Pradyu12/KALKI-WAF/proxy/internal/config"
	"github.com/Pradyu12/KALKI-WAF/proxy/internal/middleware"
	"github.com/Pradyu12/KALKI-WAF/proxy/internal/proxy"
	"github.com/Pradyu12/KALKI-WAF/proxy/internal/rules"
	"github.com/Pradyu12/KALKI-WAF/proxy/internal/telemetry"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = zerolog.New(os.Stderr).With().Timestamp().Caller().Logger()

	cfg := config.Load()
	if cfg.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	metrics, err := telemetry.NewMetrics()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize metrics")
	}

	tp, err := telemetry.InitTracer(ctx, cfg)
	if err != nil {
		log.Warn().Err(err).Msg("tracing disabled")
	} else {
		defer func() {
			if e := tp.Shutdown(ctx); e != nil {
				log.Error().Err(e).Msg("tracer shutdown error")
			}
		}()
	}

	geoipMw, err := middleware.NewGeoIP(cfg.GeoIPDBPath)
	if err != nil {
		log.Warn().Err(err).Msg("geoip disabled")
	}

	rateLimiter := middleware.NewRateLimiter(cfg.RedisURL, cfg.RateLimitThreshold, cfg.RateLimitWindow)

	ruleEngine := rules.NewEngine()
	if err := ruleEngine.LoadDefaults(); err != nil {
		log.Error().Err(err).Msg("failed to load rules")
	}

	securityHeaders := middleware.NewSecurityHeaders()
	circuitBreaker := middleware.NewCircuitBreaker(5, 30*time.Second)
	inspector := middleware.NewInspector(ruleEngine, 10*1024*1024)
	jsChallenge := middleware.NewJSChallenge(cfg.JSChallengeSecret)
	csrfProtection := middleware.NewCSRF(cfg.CSRFSecret)
	dlp := middleware.NewDLP(true, 1024*1024)

	pipeline := middleware.NewPipeline()
	pipeline.Add(geoipMw)
	pipeline.Add(rateLimiter)
	pipeline.Add(circuitBreaker)
	pipeline.Add(jsChallenge)
	pipeline.Add(csrfProtection)
	pipeline.Add(dlp)
	pipeline.Add(inspector)
	pipeline.Add(securityHeaders)

	revProxy := proxy.NewReverseProxy(cfg.UpstreamServerURL, pipeline, ruleEngine, metrics)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      revProxy.Handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Info().Int("port", cfg.Port).Str("upstream", cfg.UpstreamServerURL).Msg("proxy starting")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Info().Msg("shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("forced shutdown")
	}
}
