package platform

import (
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsRedactPathsAndQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Observe(r, "test")
	r.GET("/users/:id", func(c *gin.Context) { c.Status(204) })
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/users/private-identity?token=secret-value", nil))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), `route="/users/:id"`) {
		t.Fatal("route metric missing")
	}
	if strings.Contains(w.Body.String(), "private-identity") || strings.Contains(w.Body.String(), "secret-value") {
		t.Fatal("PII in metrics")
	}
}
func TestReadinessSeparateFromLiveness(t *testing.T) {
	r := gin.New()
	Health(r, nil, func(context.Context) error { return errors.New("dependency offline") })
	for path, want := range map[string]int{"/health": 200, "/ready": 503} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != want {
			t.Fatalf("%s status=%d", path, w.Code)
		}
	}
}
