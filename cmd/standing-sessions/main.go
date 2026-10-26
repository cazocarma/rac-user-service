// standing-sessions drains the durable user-owned identity effect journal.
package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cazocarma/rac-platform/standing/transport"
	"github.com/cazocarma/rac-user-service/internal/sessioncontrol"
	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	if err := run(); err != nil {
		// Configuration and database errors can contain credentials. Never log them.
		log.Print("standing session worker stopped unexpectedly")
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	allowHTTP := os.Getenv("RAC_ENV") == "dev" && os.Getenv("SESSION_CONTROL_ALLOW_DEV_HTTP") == "true"
	token, err := transport.CredentialsToken(os.Getenv("SESSION_TOKEN_URL"), "rac-standing-sessions", os.Getenv("SESSION_CLIENT_SECRET_FILE"), allowHTTP)
	if err != nil {
		return err
	}
	gateway, err := sessioncontrol.NewClient(os.Getenv("SESSION_CONTROL_URL"), token, allowHTTP)
	if err != nil {
		return err
	}
	if os.Getenv("DATABASE_URL") == "" {
		return sessioncontrol.ErrUnavailable
	}
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(3)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	startup, cancelStartup := context.WithTimeout(ctx, 3*time.Second)
	var role string
	err = db.QueryRowContext(startup, "SELECT current_user").Scan(&role)
	cancelStartup()
	if err != nil || role != "rac_standing_sessions" {
		return sessioncontrol.ErrUnavailable
	}
	store := &sessioncontrol.Postgres{DB: db}
	worker := &sessioncontrol.Worker{Store: store, Gateway: gateway}
	registry := prometheus.NewRegistry()
	pending := prometheus.NewGauge(prometheus.GaugeOpts{Name: "rac_standing_sessions_pending", Help: "Unfinished session effects."})
	lag := prometheus.NewGauge(prometheus.GaugeOpts{Name: "rac_standing_sessions_oldest_seconds", Help: "Age of the oldest unfinished session effect."})
	failures := prometheus.NewCounter(prometheus.CounterOpts{Name: "rac_standing_sessions_errors_total", Help: "Failed worker steps."})
	steps := prometheus.NewCounter(prometheus.CounterOpts{Name: "rac_standing_sessions_steps_total", Help: "Successful claimed steps, including fenced work."})
	registry.MustRegister(pending, lag, failures, steps)
	var mu sync.RWMutex
	var observed time.Time
	ready := false
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		mu.RLock()
		ok := ready && time.Since(observed) < 10*time.Second
		mu.RUnlock()
		if !ok {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	server := &http.Server{Addr: ":" + port, Handler: mux, ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 30 * time.Second}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ListenAndServe() }()
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(c)
	}()
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			stats, e := store.Stats(c)
			if e == nil {
				e = gateway.Check(c)
			}
			cancel()
			if e == nil {
				pending.Set(float64(stats.Pending))
				lag.Set(stats.OldestSeconds)
			}
			mu.Lock()
			observed = time.Now()
			ready = e == nil && stats.OldestSeconds < 30
			mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { stop(); <-monitorDone }()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-serverErr:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		default:
		}
		c, cancel := context.WithTimeout(ctx, 6*time.Second)
		worked, e := worker.Step(c)
		cancel()
		if e != nil {
			failures.Inc()
		} else if worked {
			steps.Inc()
		}
		if !worked || e != nil {
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	}
}
