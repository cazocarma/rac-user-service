package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/documents"
	documentstransport "github.com/cazocarma/rac-platform/documents/transport"
	"github.com/cazocarma/rac-platform/policy"
	"github.com/cazocarma/rac-platform/standing"
	"github.com/cazocarma/rac-platform/standing/transport"
)

type fixtureStandingSource struct{}

func (fixtureStandingSource) Load(context.Context, string) (standing.Snapshot, error) {
	return standing.Snapshot{Version: 1, Status: standing.Active, ObservedAt: time.Now()}, nil
}
func (fixtureStandingSource) LatestVersion(context.Context, string) (uint64, error) { return 1, nil }

// Called by the disposable Keycloak suite, not against the user's DEV realm.
func TestProvisionedStandingReaderKeycloak(t *testing.T) {
	file := os.Getenv("RAC_STANDING_IDENTITY_FIXTURE")
	if file == "" {
		t.Skip("disposable Keycloak fixture not provided")
	}
	var fixture struct {
		Issuer, JWKS, Token, RuntimeIssuer       string
		StandingOnlyToken, AlertToken, ChatToken string
		Subjects                                 map[string]string
	}
	data, err := os.ReadFile(file)
	if err != nil || json.Unmarshal(data, &fixture) != nil {
		t.Fatal("invalid identity fixture")
	}
	auth, err := NewStandingReader(StandingReaderConfig{Issuer: fixture.Issuer, JWKS: fixture.JWKS, Audience: "rac-standing", Subjects: fixture.Subjects})
	if err != nil {
		t.Fatal("invalid reader configuration")
	}
	r := httptest.NewRequest("POST", "/internal/standing", nil)
	r.Header.Set("Authorization", "Bearer "+fixture.Token)
	if auth(r) != nil {
		t.Fatal("real provisioned Keycloak reader token rejected")
	}
	// The same real signed token cannot authenticate a different service binding.
	wrong, err := NewStandingReader(StandingReaderConfig{Issuer: fixture.Issuer, JWKS: fixture.JWKS, Audience: "rac-standing", Subjects: map[string]string{"rac-match-standing": "other-subject"}})
	if err != nil || wrong(r) == nil {
		t.Fatal("reader subject binding bypassed")
	}
	// Exercise the real OAuth client-credentials exchange (HTTP Basic), then
	// authenticated authority HTTP transport, without using an admin credential.
	auth, err = NewStandingReader(StandingReaderConfig{Issuer: fixture.RuntimeIssuer, JWKS: fixture.JWKS, Audience: "rac-standing", Subjects: fixture.Subjects})
	if err != nil {
		t.Fatal("invalid runtime identity configuration")
	}
	provider, err := transport.CredentialsToken(fixture.RuntimeIssuer+"/protocol/openid-connect/token", "rac-match-standing", filepath.Join(filepath.Dir(file), "standing/match/secret"), false)
	if err != nil {
		t.Fatal("invalid OAuth token configuration")
	}
	server := httptest.NewServer(transport.Handler(fixtureStandingSource{}, auth))
	defer server.Close()
	client, err := transport.NewClient(server.URL, provider, true)
	if err != nil {
		t.Fatal("invalid authority client configuration")
	}
	if snapshot, err := client.Load(context.Background(), "fixture-subject"); err != nil || snapshot.Version != 1 {
		t.Fatal("real OAuth credentials failed authenticated authority HTTP exchange")
	}
	documentBindings := map[string]string{"rac-match-standing": fixture.Subjects["rac-match-standing"], "rac-chat-standing": fixture.Subjects["rac-chat-standing"]}
	documentAuth, err := NewDocumentsReader(StandingReaderConfig{Issuer: fixture.Issuer, JWKS: fixture.JWKS, Audience: "rac-documents", Subjects: documentBindings})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		token string
		want  bool
	}{{fixture.Token, true}, {fixture.ChatToken, true}, {fixture.StandingOnlyToken, false}, {fixture.AlertToken, false}} {
		if tc.token == "" {
			t.Fatal("missing document identity fixture")
		}
		r := httptest.NewRequest("POST", "/internal/documents", nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		if (documentAuth(r) == nil) != tc.want {
			t.Fatal("real document token scope isolation failed")
		}
	}
	documentAuth, err = NewDocumentsReader(StandingReaderConfig{Issuer: fixture.RuntimeIssuer, JWKS: fixture.JWKS, Audience: "rac-documents", Subjects: documentBindings})
	if err != nil {
		t.Fatal(err)
	}
	documentServer := httptest.NewServer(documentstransport.Handler(fixtureDocumentSource{}, documentAuth))
	defer documentServer.Close()
	documentClient, err := documentstransport.NewClient(documentServer.URL, documentstransport.TokenProvider(provider), true)
	if err != nil {
		t.Fatal(err)
	}
	query := documents.Query{AccountID: "11111111-1111-4111-8111-111111111111", Role: documents.Client, Capability: standing.RequestBooking, Locale: "es"}
	if err := documents.Check(context.Background(), documentClient, query, time.Second); !errors.Is(err, documents.ErrRequired) {
		t.Fatal("real OAuth document authority exchange failed", err)
	}
}

type fixtureDocumentSource struct{}

func (fixtureDocumentSource) ReadDocuments(_ context.Context, q documents.Query) (documents.Observation, error) {
	now := time.Now()
	s := documents.Snapshot{ObservedAt: now, Policy: policy.Version{ID: "fixture-policy", State: policy.Approved, ApprovedBy: "fixture-reviewer", EffectiveAt: now.Add(-time.Hour)}}
	for i, k := range []documents.Kind{documents.TermsClient, documents.CommunityRules, documents.Privacy, documents.SafetyRules} {
		id := fmt.Sprintf("11111111-1111-4111-8111-%012d", i+1)
		s.Documents = append(s.Documents, documents.Document{ID: id, Kind: k, MaterialVersion: id, SHA256: [32]byte{byte(i + 1)}, Approved: true, PublishedAt: now.Add(-time.Hour)})
	}
	return documents.Observation{Query: q, Revision: 1, Snapshot: s}, nil
}

func TestStandingAuthorityRolloutConfiguration(t *testing.T) {
	t.Setenv("STANDING_ENFORCEMENT_ENABLED", "false")
	if server, err := StandingAuthorityFromEnvironment(nil); server != nil || err != nil {
		t.Fatal("disabled rollout started listener")
	}
	t.Setenv("STANDING_ENFORCEMENT_ENABLED", "typo")
	if server, err := StandingAuthorityFromEnvironment(nil); server != nil || err == nil {
		t.Fatal("invalid rollout enabled listener")
	}
	t.Setenv("STANDING_ENFORCEMENT_ENABLED", "true")
	t.Setenv("STANDING_SUBJECTS_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := StandingAuthorityFromEnvironment(nil); err == nil {
		t.Fatal("missing bindings accepted")
	}
	file := filepath.Join(t.TempDir(), "subjects.json")
	if err := os.WriteFile(file, []byte(`{"rac-match-standing":"machine-subject","rac-chat-standing":"chat-subject","rac-alert-standing":"alert-subject"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STANDING_SUBJECTS_FILE", file)
	t.Setenv("OIDC_ISSUER", "https://issuer.example/realms/rac")
	t.Setenv("STANDING_JWKS_URL", "https://issuer.example/realms/rac/certs")
	t.Setenv("RAC_ENV", "qa")
	server, err := StandingAuthorityFromEnvironment(nil)
	if err != nil || server == nil || server.Addr != ":8082" {
		t.Fatal("internal server configuration rejected")
	}
	w := httptest.NewRecorder()
	server.Handler.ServeHTTP(w, httptest.NewRequest("POST", "/internal/standing", nil))
	if w.Code != 401 {
		t.Fatal("authority exposed without authentication")
	}
	w = httptest.NewRecorder()
	server.Handler.ServeHTTP(w, httptest.NewRequest("POST", "/api/user/me", nil))
	if w.Code != 404 {
		t.Fatal("public routes exposed by internal listener")
	}
}
