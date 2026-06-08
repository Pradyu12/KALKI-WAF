package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

type Metrics struct {
	requestsTotal     prometheus.Counter
	blockedTotal      *prometheus.CounterVec
	requestDuration   prometheus.Histogram
	upstreamTimeouts  prometheus.Counter
	activeConnections prometheus.Gauge
}

func NewMetrics() (*Metrics, error) {
	m := &Metrics{
		requestsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "kalki_requests_total",
			Help: "Total number of requests processed",
		}),
		blockedTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "kalki_blocked_total",
			Help: "Total number of blocked requests by threat type",
		}, []string{"threat_type"}),
		requestDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "kalki_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		upstreamTimeouts: promauto.NewCounter(prometheus.CounterOpts{
			Name: "kalki_upstream_timeouts_total",
			Help: "Total number of upstream timeouts",
		}),
		activeConnections: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "kalki_active_connections",
			Help: "Current number of active connections",
		}),
	}

	http.Handle("/metrics", promhttp.Handler())
	go func() {
		http.ListenAndServe(":9090", nil)
	}()

	return m, nil
}

func (m *Metrics) IncRequests() {
	m.requestsTotal.Inc()
	m.activeConnections.Inc()
}

func (m *Metrics) IncBlocked(threatType string) {
	m.blockedTotal.WithLabelValues(threatType).Inc()
}

func (m *Metrics) ObserveLatency(seconds float64) {
	m.requestDuration.Observe(seconds)
}

func (m *Metrics) IncUpstreamTimeouts() {
	m.upstreamTimeouts.Inc()
}

func (m *Metrics) DecConnections() {
	m.activeConnections.Dec()
}
