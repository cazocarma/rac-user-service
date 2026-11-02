package listingreview

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/staff"
	"github.com/cazocarma/rac-user-service/internal/config"
	httpapi "github.com/cazocarma/rac-user-service/internal/http"
)

func fixtureCorrection() correctionCommand {
	return correctionCommand{EventID: "77777777-7777-4777-8777-777777777777", ExpectedVersion: "3", SHA256: strings.Repeat("a", 64), Decision: "changes_requested", ReasonCatalogVersion: "fixture-reasons-1", ReasonCode: "incomplete_description"}
}

func correctionRequest(handler http.Handler, raw, credential string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/internal/listings/revisions/55555555-5555-4555-8555-555555555555/decisions", strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestCorrectionAuthorizationAndInput(t *testing.T) {
	access, token := readerAccess(t)
	owner := &Server{access: access, policy: fixtureID, now: time.Now}
	handler := (&Corrector{owner: owner}).Handler()
	raw, _ := json.Marshal(fixtureCorrection())
	for _, tc := range []struct {
		role, audience string
		want           int
	}{
		{"", "", 401}, {"support", staff.ListingsAudience, 403}, {"legal", staff.ListingsAudience, 403},
		{"business_admin", staff.ListingsAudience, 403}, {"admin", staff.ListingsAudience, 403},
		{"ts_agent", staff.AdminAudience, 401}, {"ts_lead", staff.DocumentsAudience, 401},
	} {
		credential := ""
		if tc.role != "" {
			credential = token(tc.role, tc.audience)
		}
		w := correctionRequest(handler, string(raw), credential)
		if w.Code != tc.want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("wrong persona reached writer", tc.role, w.Code)
		}
	}
	for _, role := range []string{"ts_agent", "ts_lead"} {
		credential := token(role, staff.ListingsAudience)
		var command map[string]any
		json.Unmarshal(raw, &command)
		for key, value := range map[string]any{
			"actor": fixtureID, "policy_version": fixtureID, "approved_by": fixtureID,
			"expected_version": 3,
			"sha256":           "not-a-hash", "event_id": "00000000-0000-0000-0000-000000000000",
			"decision": "approved", "reason_code": "free text", "reason_catalog_version": "",
		} {
			var body map[string]any
			json.Unmarshal(raw, &body)
			body[key] = value
			encoded, _ := json.Marshal(body)
			if w := correctionRequest(handler, string(encoded), credential); w.Code != 400 {
				t.Fatal("ambiguous authority/command reached persistence", key, w.Code)
			}
		}
		for _, version := range []string{"-1", "03", "+3", "3.0", "9223372036854775807", "9223372036854775808", ""} {
			body := fixtureCorrection()
			body.ExpectedVersion = version
			encoded, _ := json.Marshal(body)
			if w := correctionRequest(handler, string(encoded), credential); w.Code != 400 {
				t.Fatal("invalid version reached persistence", version, w.Code)
			}
		}
		for _, body := range []string{string(raw) + `{}`, strings.Replace(string(raw), `"decision":`, `"decision":"rejected","decision":`, 1), strings.Repeat("x", 4097)} {
			if w := correctionRequest(handler, body, credential); w.Code != 400 {
				t.Fatal("ambiguous body reached writer", w.Code)
			}
		}
		for _, media := range []string{"text/plain", "application/json; charset=latin1", "application/json; boundary=test", "application/json; charset=utf-8; boundary=test"} {
			req := httptest.NewRequest("POST", "/internal/listings/revisions/"+fixtureID+"/decisions", strings.NewReader(string(raw)))
			req.Header.Set("Authorization", "Bearer "+credential)
			req.Header.Set("Content-Type", media)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != 400 {
				t.Fatal("unrecognized media type", media, w.Code)
			}
		}
	}
	// Neither customer API nor read-only ingress exposes this command. The
	// correction ingress does not expose content reads either.
	for _, target := range []http.Handler{owner.Handler(), httpapi.New(nil, config.Config{}).Router()} {
		w := correctionRequest(target, string(raw), token("ts_lead", staff.ListingsAudience))
		if w.Code != 404 {
			t.Fatal("correction exposed on unrelated router", w.Code)
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/internal/listings/queue", nil))
	if w.Code != 404 {
		t.Fatal("writer exposed read queue")
	}
}
