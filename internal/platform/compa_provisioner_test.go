package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProvisionerOnlyAssignsFixedCompaRole(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/realms/rentacompa/protocol/openid-connect/token":
			r.ParseForm()
			if r.Form.Get("client_id") != "rac-compa-provisioner" || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_secret") != "test-secret" {
				t.Error("wrong service credentials")
			}
			w.Write([]byte(`{"access_token":"test-service-token"}`))
		case "/admin/realms/rentacompa/users/verified-sub/role-mappings/realm":
			if r.Method != "POST" {
				t.Error("wrong role mutation")
			}
			var body []map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if len(body) != 1 || body[0]["name"] != "compa" || body[0]["id"] != "11111111-1111-4111-8111-111111111111" {
				t.Error("unexpected privilege assignment")
			}
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	p := CompaProvisioner{RoleIDFile: roleFixture(t), Base: server.URL, Secret: "test-secret", Client: server.Client()}
	if err := p.Grant(context.Background(), "verified-sub"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}

func TestProvisionerFailsClosedWithoutLeakingCredentials(t *testing.T) {
	for _, status := range []int{401, 403, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status); w.Write([]byte("test-secret")) }))
		p := CompaProvisioner{RoleIDFile: roleFixture(t), Base: server.URL, Secret: "test-secret", Client: server.Client()}
		err := p.Grant(context.Background(), "verified-sub")
		if err == nil || strings.Contains(err.Error(), "test-secret") {
			t.Fatal("unexpected identity error", err)
		}
		server.Close()
	}
	p := CompaProvisioner{}
	if p.Grant(context.Background(), "verified-sub") == nil {
		t.Fatal("missing config accepted")
	}
}

func roleFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "compa-role-id")
	if err := os.WriteFile(path, []byte("11111111-1111-4111-8111-111111111111\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestProvisionerRejectsMissingOrInvalidRoleFile(t *testing.T) {
	for _, value := range []string{"", "admin", "00000000-0000-0000-0000-000000000000", strings.Repeat("x", 200)} {
		path := filepath.Join(t.TempDir(), "role")
		os.WriteFile(path, []byte(value), 0600)
		p := CompaProvisioner{Base: "http://not-contacted.invalid", Secret: "never-exposed", RoleIDFile: path}
		if err := p.Grant(context.Background(), "verified-sub"); err == nil || strings.Contains(err.Error(), "never-exposed") {
			t.Fatal("invalid role file accepted or secret exposed")
		}
	}
}
