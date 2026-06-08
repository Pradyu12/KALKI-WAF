package middleware

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

type RateLimiter struct {
	client    *redis.Client
	threshold int
	window    int
	local     *sync.Map
	useRedis  bool
}

func NewRateLimiter(redisURL string, threshold, window int) *RateLimiter {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Warn().Err(err).Msg("redis not available, using local rate limiter")
		return &RateLimiter{
			threshold: threshold,
			window:    window,
			local:     &sync.Map{},
		}
	}

	client := redis.NewClient(opts)
	if err := client.Ping(context.Background()).Err(); err != nil {
		log.Warn().Err(err).Msg("redis ping failed, using local rate limiter")
		return &RateLimiter{
			threshold: threshold,
			window:    window,
			local:     &sync.Map{},
		}
	}

	return &RateLimiter{
		client:    client,
		threshold: threshold,
		window:    window,
		local:     &sync.Map{},
		useRedis:  true,
	}
}

func (rl *RateLimiter) Process(ctx *Context) {
	ip := clientIP(ctx.Request)
	if ip == "" {
		return
	}

	if rl.useRedis {
		if rl.redisCheck(ip) {
			ctx.Blocked = true
			ctx.ThreatType = "rate_limited"
			httpError(ctx.Response, "Rate limit exceeded. Try again later.")
			return
		}
	} else {
		if rl.localCheck(ip) {
			ctx.Blocked = true
			ctx.ThreatType = "rate_limited"
			httpError(ctx.Response, "Rate limit exceeded. Try again later.")
		}
	}
}

func (rl *RateLimiter) redisCheck(ip string) bool {
	ctx := context.Background()
	now := time.Now().Unix()
	windowKey := "ratelimit:" + ip + ":" + strconv.FormatInt(now/int64(rl.window), 10)

	count, err := rl.client.Incr(ctx, windowKey).Result()
	if err != nil {
		return false
	}
	if count == 1 {
		rl.client.Expire(ctx, windowKey, time.Duration(rl.window)*time.Second)
	}
	return int(count) > rl.threshold
}

type counter struct {
	count    int
	windowStart int64
}

func (rl *RateLimiter) localCheck(ip string) bool {
	now := time.Now().Unix()
	windowKey := now / int64(rl.window)

	val, _ := rl.local.LoadOrStore(ip, &counter{windowStart: windowKey})
	c := val.(*counter)

	if c.windowStart != windowKey {
		c.count = 1
		c.windowStart = windowKey
		return false
	}

	c.count++
	return c.count > rl.threshold
}

func splitHostPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return splitHostPort(r.RemoteAddr)
}
