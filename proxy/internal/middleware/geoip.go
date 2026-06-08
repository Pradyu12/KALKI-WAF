package middleware

import (
	"net"
	"strings"

	"github.com/oschwald/geoip2-golang"
	"github.com/rs/zerolog/log"
)

type GeoIP struct {
	db      *geoip2.Reader
	blocked map[string]bool
}

func NewGeoIP(dbPath string) (*GeoIP, error) {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, err
	}
	log.Info().Str("path", dbPath).Msg("geoip database loaded")
	return &GeoIP{db: db, blocked: make(map[string]bool)}, nil
}

func (g *GeoIP) Process(ctx *Context) {
	ipStr := clientIP(ctx.Request)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}

	record, err := g.db.Country(ip)
	if err != nil || record == nil {
		return
	}

	country := record.Country.IsoCode
	if country == "" {
		return
	}

	if g.blocked[country] {
		ctx.Blocked = true
		ctx.ThreatType = "geoip_blocked"
		httpError(ctx.Response, "Access denied by country policy")
		return
	}

	ctx.Request.Header.Set("X-GeoIP-Country", country)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func (g *GeoIP) SetBlockedCountries(countries []string) {
	g.blocked = make(map[string]bool)
	for _, c := range countries {
		g.blocked[strings.ToUpper(strings.TrimSpace(c))] = true
	}
}

func httpError(w http.ResponseWriter, msg string) {
	http.Error(w, msg, http.StatusForbidden)
}
