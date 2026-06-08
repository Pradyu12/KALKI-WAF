package middleware

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

type CSRF struct {
	secret []byte
}

func NewCSRF(secret string) *CSRF {
	return &CSRF{secret: []byte(secret)}
}

func (c *CSRF) Process(ctx *Context) {
	if ctx.Request.Method == "GET" || ctx.Request.Method == "HEAD" || ctx.Request.Method == "OPTIONS" {
		c.setToken(ctx)
		return
	}
	token := ctx.Request.Header.Get("X-CSRF-Token")
	if token == "" {
		token = ctx.Request.FormValue("_csrf")
	}
	if token == "" {
		ctx.Blocked = true
		ctx.ThreatType = "csrf_missing"
		httpError(ctx.Response, "CSRF token required")
		return
	}
	if !c.validateToken(token, clientIP(ctx.Request)) {
		ctx.Blocked = true
		ctx.ThreatType = "csrf_invalid"
		httpError(ctx.Response, "CSRF token invalid")
	}
}

func (c *CSRF) setToken(ctx *Context) {
	token := c.generateToken(clientIP(ctx.Request))
	ctx.Response.Header().Set("X-CSRF-Token", token)
}

func (c *CSRF) generateToken(ip string) string {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	h := sha256.New()
	h.Write([]byte(ip))
	h.Write(c.secret)
	h.Write(nonce)
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString(nonce), sig)
}

func (c *CSRF) validateToken(token, ip string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	h := sha256.New()
	h.Write([]byte(ip))
	h.Write(c.secret)
	h.Write(nonce)
	expected := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return parts[1] == expected
}
