package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port               int
	UpstreamServerURL  string
	RedisURL           string
	GeoIPDBPath        string
	RateLimitThreshold int
	RateLimitWindow    int
	BlockedCountries   []string
	TrustedIPs         []string
	Debug              bool
	JSChallengeSecret  string
	CSRFSecret         string
}

func Load() *Config {
	return &Config{
		Port:               getEnvInt("PROXY_PORT", 8080),
		UpstreamServerURL:  getEnv("UPSTREAM_SERVER_URL", "http://127.0.0.1:8000"),
		RedisURL:           getEnv("REDIS_URL", "redis://localhost:6379"),
		GeoIPDBPath:        getEnv("GEOIP_DB_PATH", "GeoLite2-Country.mmdb"),
		RateLimitThreshold: getEnvInt("RATE_LIMIT_THRESHOLD", 50),
		RateLimitWindow:    getEnvInt("RATE_LIMIT_WINDOW", 10),
		BlockedCountries:   splitEnv("BLOCKED_COUNTRIES"),
		TrustedIPs:         splitEnv("TRUSTED_IPS"),
		Debug:              os.Getenv("DEBUG") == "true",
		JSChallengeSecret:  getEnv("JS_CHALLENGE_SECRET", "kalki-js-challenge-secret"),
		CSRFSecret:         getEnv("CSRF_SECRET", "kalki-csrf-secret"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func splitEnv(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
