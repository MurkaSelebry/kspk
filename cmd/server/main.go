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

	// Restrictive router: only "/" and "/cats" are allowed; others -> "Oops"
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			// Serve Prometheus metrics at root
			metrics.Handler().ServeHTTP(w, r)
			return
		case "/cats":
			metrics.ObserveRequest(r.Method, r.URL.Path, func() int {
				status, contentType, body := catSvc.FetchRandomCatImage(r.Context())
				if contentType != "" {
					w.Header().Set("Content-Type", contentType)
				} else {
					w.Header().Set("Content-Type", "application/octet-stream")
				}
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(status)
				_, _ = w.Write(body)
				return status
			})
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("Oops"))
			return
		}
	})

	addr := ":8080"
	log.Printf("Listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
