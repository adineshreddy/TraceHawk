package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var probeMutex sync.Mutex
var probeStatus = "starting"
var probeSeen = time.Now()
var publishedRecords atomic.Int64

func workerState(status string) {
	probeMutex.Lock()
	probeStatus, probeSeen = status, time.Now()
	probeMutex.Unlock()
}

func startProbes() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		probeMutex.Lock()
		status, fresh := probeStatus, time.Since(probeSeen) < 20*time.Second
		probeMutex.Unlock()
		if !fresh {
			status = "stalled"
		}
		ready := status == "ready" && fresh
		if r.URL.Path == "/metrics" {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			value := 0
			if ready {
				value = 1
			}
			fmt.Fprintf(w, "tracehawk_worker_ready %d\n# TYPE tracehawk_published_records_total counter\ntracehawk_published_records_total %d\n", value, publishedRecords.Load())
			return
		}
		if r.URL.Path != "/health/live" && r.URL.Path != "/health/ready" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if (r.URL.Path == "/health/live" && !fresh) || (r.URL.Path == "/health/ready" && !ready) {
			w.WriteHeader(503)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
	})
	server := &http.Server{Addr: ":9100", Handler: mux, ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Println(`{"component":"collector","event":"probe_server_failed"}`)
			os.Exit(1)
		}
	}()
}

func probeCheck() {
	c := &http.Client{Timeout: 3 * time.Second}
	r, err := c.Get("http://127.0.0.1:9100/health/live")
	if err != nil {
		os.Exit(1)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		os.Exit(1)
	}
}
