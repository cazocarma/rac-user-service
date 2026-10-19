package platform

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"
)

func Observe(r *gin.Engine, service string) {
	registry := prometheus.NewRegistry()
	count := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rac_http_requests_total", Help: "HTTP requests by route"}, []string{"service", "method", "route", "status"})
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "rac_http_request_duration_seconds", Help: "HTTP latency", Buckets: prometheus.DefBuckets}, []string{"service", "method", "route"})
	registry.MustRegister(count, duration, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	r.Use(func(c *gin.Context) {
		start := time.Now()
		var id [12]byte
		_, _ = rand.Read(id[:])
		requestID := hex.EncodeToString(id[:])
		c.Header("X-Request-ID", requestID)
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		if route == "/metrics" || route == "/health" || route == "/ready" {
			return
		}
		count.WithLabelValues(service, c.Request.Method, route, strconv.Itoa(c.Writer.Status())).Inc()
		duration.WithLabelValues(service, c.Request.Method, route).Observe(time.Since(start).Seconds())
		logger.Info("http_request", "service", service, "environment", os.Getenv("RAC_ENV"), "method", c.Request.Method, "route", route, "status", c.Writer.Status(), "duration_ms", time.Since(start).Milliseconds(), "request_id", requestID)
	})
	r.GET("/metrics", gin.WrapH(promhttp.HandlerFor(registry, promhttp.HandlerOpts{})))
}
func Health(r *gin.Engine, db *sql.DB, dependency func(context.Context) error) {
	r.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	r.GET("/ready", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()
		if db != nil {
			if err := db.PingContext(ctx); err != nil {
				c.JSON(503, gin.H{"status": "not_ready"})
				return
			}
		}
		if dependency != nil {
			if err := dependency(ctx); err != nil {
				c.JSON(503, gin.H{"status": "not_ready"})
				return
			}
		}
		c.JSON(200, gin.H{"status": "ready"})
	})
}
