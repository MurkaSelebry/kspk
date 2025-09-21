package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"kasper/internal/cat"
	"kasper/internal/host"
	"kasper/internal/metrics"
)

func main() {
	// Detect host type once at startup
	hostType := host.DetectHostType()

	// Setup Prometheus metrics (counter, histogram, and host type gauge)
	metrics.MustRegister(hostType)

	client := &http.Client{Timeout: 10 * time.Second}
	catSvc := cat.NewService(client, os.Getenv("THECATAPI_KEY"))

	http.Handle("/metrics", metrics.Handler())
	http.HandleFunc("/cat", func(w http.ResponseWriter, r *http.Request) {
		metrics.ObserveRequest(r.Method, r.URL.Path, func() int {
			status, body := catSvc.FetchRandomCat(r.Context())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
			return status
		})
	})

	addr := ":8080"
	log.Printf("Listening on ", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
