package middleware

type SecurityHeaders struct {
	headers map[string]string
}

func NewSecurityHeaders() *SecurityHeaders {
	return &SecurityHeaders{
		headers: map[string]string{
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "DENY",
			"X-XSS-Protection":          "0",
			"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
			"Referrer-Policy":           "strict-origin-when-cross-origin",
			"Permissions-Policy":        "camera=(), microphone=(), geolocation=(), interest-cohort=()",
		},
	}
}

func (h *SecurityHeaders) Process(ctx *Context) {
	for key, value := range h.headers {
		ctx.Response.Header().Set(key, value)
	}
}
