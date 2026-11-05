package listingreview

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/staff"
	"github.com/cazocarma/rac-user-service/internal/config"
	httpapi "github.com/cazocarma/rac-user-service/internal/http"
)

func TestPhotoApprovalAuthorizationAndInputBeforePersistence(t *testing.T) {
	access, token := readerAccess(t)
	a := &photoApprover{owner: &Server{access: access, policy: fixtureID, now: time.Now}, slots: make(chan struct{}, 2)}
	handler := a.Handler()
	path := "/internal/listings/revisions/" + fixtureID + "/photo-approval"
	body := `{"event_id":"` + fixtureID + `","expected_version":"1","sha256":"` + strings.Repeat("a", 64) + `"}`
	call := func(path, body, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		auth string
		want int
	}{
		{"", 401}, {token("support", staff.ListingsAudience), 403}, {token("legal", staff.ListingsAudience), 403},
		{token("business_admin", staff.ListingsAudience), 403}, {token("ts_agent", staff.AdminAudience), 401},
	} {
		if w := call(path, body, tc.auth); w.Code != tc.want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("private approval authorization bypass", w.Code, tc.want)
		}
	}
	auth := token("ts_agent", staff.ListingsAudience)
	for _, bad := range []string{`{"event_id":"bad"}`, `{"event_id":"` + fixtureID + `","expected_version":"1","sha256":"` + strings.Repeat("a", 64) + `","actor":"forged"}`, `{`} {
		if w := call(path, bad, auth); w.Code != 400 {
			t.Fatal("invalid command reached DB", w.Code)
		}
	}
	for _, bad := range []string{path + "?", path + "?destination=outside", strings.Replace(path, fixtureID, "invalid", 1)} {
		if w := call(bad, body, auth); w.Code != 400 {
			t.Fatal("invalid target reached DB", w.Code)
		}
	}
	// Two concurrent slots already in use: no persistence/storage is attempted.
	a.slots <- struct{}{}
	a.slots <- struct{}{}
	if w := call(path, body, auth); w.Code != 503 {
		t.Fatal("unbounded promotion ingress", w.Code)
	}
	public := httpapi.New(nil, config.Config{}).Router()
	w := httptest.NewRecorder()
	public.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
	if w.Code != 404 {
		t.Fatal("private photo approval exposed on customer API", w.Code)
	}
}
