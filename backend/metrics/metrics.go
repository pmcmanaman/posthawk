package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ValidationRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "posthawk_validation_requests_total",
			Help: "Total number of email validation requests",
		},
		[]string{"status", "validation_type", "client_id", "domain"},
	)

	ValidationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "posthawk_validation_duration_seconds",
			Help:    "Time spent validating emails",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"validation_type", "domain"},
	)

	ActiveRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "posthawk_active_requests",
			Help: "Number of active validation requests",
		},
	)

	RateLimitExceeded = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "posthawk_rate_limit_exceeded_total",
			Help: "Number of times rate limit was exceeded",
		},
		[]string{"client_id", "domain"},
	)

	ValidationErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "posthawk_validation_errors_total",
			Help: "Total number of validation errors",
		},
		[]string{"type", "client_id", "domain"},
	)

	RequestLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "posthawk_request_latency_seconds",
			Help:    "Request latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint", "status"},
	)

	RequestSize = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "posthawk_request_size_bytes",
			Help: "Request size in bytes",
		},
		[]string{"method", "endpoint"},
	)

	ResponseSize = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "posthawk_response_size_bytes",
			Help: "Response size in bytes",
		},
		[]string{"method", "endpoint", "status"},
	)
)

func RegisterMetrics() {
	prometheus.MustRegister(
		ValidationRequests,
		ValidationDuration,
		ActiveRequests,
		RateLimitExceeded,
		ValidationErrors,
		RequestLatency,
		RequestSize,
		ResponseSize,
	)
}
