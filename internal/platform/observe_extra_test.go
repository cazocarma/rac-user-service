package platform

import (
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestExtraMetricsStayReadableWhenScraperOffersGzip(t *testing.T) {
	r := gin.New()
	Observe(r, "fixture", func(w io.Writer) { fmt.Fprintln(w, "fixture_extra 1") })
	request := httptest.NewRequest("GET", "/metrics", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	response := httptest.NewRecorder()
	r.ServeHTTP(response, request)
	if response.Code != 200 || response.Header().Get("Content-Encoding") != "" {
		t.Fatal("metrics response mixes incompatible encodings")
	}
	if !strings.Contains(response.Body.String(), "fixture_extra 1") || !strings.Contains(response.Body.String(), "go_goroutines") {
		t.Fatal("SDK or registry metrics disappeared from the response")
	}
}
