package middleware

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

type state int32

const (
	stateClosed   state = 0
	stateHalfOpen state = 1
	stateOpen     state = 2
)

type CircuitBreaker struct {
	failureThreshold int
	resetTimeout     time.Duration
	state            int32
	failureCount     int32
	lastFailureTime  atomic.Value
	mu               sync.Mutex
}

func NewCircuitBreaker(threshold int, resetTimeout time.Duration) *CircuitBreaker {
	cb := &CircuitBreaker{
		failureThreshold: threshold,
		resetTimeout:     resetTimeout,
	}
	cb.lastFailureTime.Store(time.Time{})
	return cb
}

func (cb *CircuitBreaker) Process(ctx *Context) {
	if atomic.LoadInt32(&cb.state) == int32(stateOpen) {
		lastFail := cb.lastFailureTime.Load().(time.Time)
		if time.Since(lastFail) > cb.resetTimeout {
			atomic.StoreInt32(&cb.state, int32(stateHalfOpen))
			log.Debug().Msg("circuit breaker half-open")
		} else {
			ctx.Blocked = true
			ctx.ThreatType = "circuit_breaker"
			httpError(ctx.Response, "Service temporarily unavailable")
			return
		}
	}
}

func (cb *CircuitBreaker) RecordFailure() {
	count := atomic.AddInt32(&cb.failureCount, 1)
	cb.lastFailureTime.Store(time.Now())

	if count >= int32(cb.failureThreshold) {
		atomic.StoreInt32(&cb.state, int32(stateOpen))
		log.Warn().Int32("failures", count).Msg("circuit breaker opened")
	}
}

func (cb *CircuitBreaker) RecordSuccess() {
	atomic.StoreInt32(&cb.failureCount, 0)
	atomic.StoreInt32(&cb.state, int32(stateClosed))
}
