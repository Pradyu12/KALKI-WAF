package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

type JSChallenge struct {
	secret []byte
}

type challengePayload struct {
	IP        string `json:"ip"`
	ExpiresAt int64  `json:"exp"`
}

func NewJSChallenge(secret string) *JSChallenge {
	return &JSChallenge{secret: []byte(secret)}
}

func (j *JSChallenge) Process(ctx *Context) {
	cookie, err := ctx.Request.Cookie("kalki_challenge")
	if err == nil && j.verifyToken(cookie.Value, clientIP(ctx.Request)) {
		return
	}
	if ctx.Request.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		ctx.Blocked = true
		ctx.ThreatType = "js_challenge"
		httpError(ctx.Response, "JavaScript challenge required")
		return
	}
	ctx.Response.Header().Set("Content-Type", "text/html; charset=utf-8")
	ctx.Response.WriteHeader(http.StatusOK)
	tmpl := `<html><body>
		<script>
			document.cookie = "kalki_challenge={{.Token}}; path=/; max-age=300";
			window.location.reload();
		</script>
	</body></html>`
	token := j.generateToken(clientIP(ctx.Request))
	t, _ := template.New("challenge").Parse(tmpl)
	t.Execute(ctx.Response, map[string]string{"Token": token})
	ctx.Blocked = true
	ctx.ThreatType = "js_challenge_pending"
}

func (j *JSChallenge) generateToken(ip string) string {
	payload := challengePayload{
		IP:        ip,
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}
	data, _ := json.Marshal(payload)
	encoded := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, j.secret)
	mac.Write([]byte(encoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s.%s", encoded, sig)
}

func (j *JSChallenge) verifyToken(token, ip string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	mac := hmac.New(sha256.New, j.secret)
	mac.Write([]byte(parts[0]))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var payload challengePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return false
	}
	return payload.IP == ip && time.Now().Unix() < payload.ExpiresAt
}
