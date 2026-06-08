package middleware

import (
	"net/http"
)

type Context struct {
	Request     *http.Request
	Response    http.ResponseWriter
	Blocked     bool
	ThreatScore float64
	ThreatType  string
}

type Middleware interface {
	Process(ctx *Context)
}

type Pipeline struct {
	middlewares []Middleware
}

func NewPipeline() *Pipeline {
	return &Pipeline{}
}

func (p *Pipeline) Add(m Middleware) {
	if m != nil {
		p.middlewares = append(p.middlewares, m)
	}
}

func (p *Pipeline) Execute(ctx *Context) {
	for _, m := range p.middlewares {
		m.Process(ctx)
		if ctx.Blocked {
			return
		}
	}
}
