package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	requestTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests",
	}, []string{"method", "path", "status"})

	requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "http_request_duration_seconds",
		Help: "HTTP request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})

	hostTypeGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "host_type",
		Help: "Type of host running the server: container, vm, physical",
	}, []string{"type"})
)

// MustRegister sets initial host type gauge and registers collectors.
func MustRegister(hostType string) {
	prometheus.MustRegister(requestTotal, requestDuration, hostTypeGauge)
	// set host type gauge: 1 for the active type label
	hostTypeGauge.WithLabelValues(hostType).Set(1)
}

// ObserveRequest wraps a handler to record metrics.
func ObserveRequest(method, path string, fn func() int) {
	timer := prometheus.NewTimer(requestDuration.WithLabelValues(method, path))
	defer timer.ObserveDuration()
	status := fn()
	requestTotal.WithLabelValues(method, path, http.StatusText(status)).Inc()
}

func Handler() http.Handler {
	return promhttp.Handler()
}
