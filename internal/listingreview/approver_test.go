package listingreview

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/staff"
)

func TestApprovalAuthorizationBeforePersistence(t *testing.T) {
	access, token := readerAccess(t)
	handler := (&Approver{owner: &Server{access: access, policy: fixtureID, now: time.Now}}).Handler()
	path := "/internal/listings/revisions/" + fixtureID + "/approval"
	valid := `{"event_id":"` + fixtureID + `","expected_version":"1","sha256":"` + strings.Repeat("a", 64) + `"}`
	for _, tc := range []struct {
		name, auth, contentType, body string
		want                          int
	}{
		{"anonymous", "", "application/json", valid, 401},
		{"support", token("support", staff.ListingsAudience), "application/json", valid, 403},
		{"other audience", token("ts_agent", staff.AdminAudience), "application/json", valid, 401},
		{"form body", token("ts_agent", staff.ListingsAudience), "text/plain", valid, 400},
		{"unknown field", token("ts_agent", staff.ListingsAudience), "application/json", strings.TrimSuffix(valid, "}") + `,"decision":"approved"}`, 400},
		{"leading zero", token("ts_agent", staff.ListingsAudience), "application/json", strings.Replace(valid, `"1"`, `"01"`, 1), 400},
		{"short hash", token("ts_agent", staff.ListingsAudience), "application/json", strings.Replace(valid, strings.Repeat("a", 64), "abc", 1), 400},
	} {
		req := httptest.NewRequest("POST", path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", tc.contentType)
		if tc.auth != "" {
			req.Header.Set("Authorization", "Bearer "+tc.auth)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != tc.want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(tc.name, w.Code, w.Body.String())
		}
	}
}
