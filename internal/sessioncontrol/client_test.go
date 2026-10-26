package sessioncontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func fixtureClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewTLSServer(handler)
	t.Cleanup(s.Close)
	c, err := NewClient(s.URL+"/realms/rentacompa/rac-sessions", func(context.Context) (string, error) { return "fixture-canary", nil }, false)
	if err != nil {
		t.Fatal(err)
	}
	c.http.Transport = s.Client().Transport // Trust only this fixture's CA; preserve redirect policy.
	return c
}

func TestSessionProtocolValidation(t *testing.T) {
	subject := "00000000-0000-0000-0000-000000000001"
	for _, response := range []string{
		`{"complete":true,"sessions":[{"id":"opaque~id","offline":false}]}`,
		`{"complete":true,"sessions":[]}`,
		`{"complete":false,"sessions":[]}`, `{"sessions":[]}`, `{"complete":true}`,
		`{"complete":true,"sessions":null}`, `{"complete":true,"sessions":[{"id":"id"}]}`,
		`{"complete":true,"sessions":[{"id":"id","offline":false,"secret":"canary"}]}`,
		`{"complete":true,"sessions":[{"id":"id","offline":false},{"id":"id","offline":false}]}`,
		`{"complete":true,"sessions":[]} {}`, strings.Repeat(" ", 3<<20) + `{}`,
	} {
		t.Run(fmt.Sprint(len(response), response[:min(25, len(response))]), func(t *testing.T) {
			c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer fixture-canary" || r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/users/"+subject+"/sessions") {
					t.Error("invalid authenticated request")
				}
				fmt.Fprint(w, response)
			})
			refs, err := c.Snapshot(context.Background(), subject)
			valid := response == `{"complete":true,"sessions":[{"id":"opaque~id","offline":false}]}` || response == `{"complete":true,"sessions":[]}`
			if (err == nil) != valid {
				t.Fatal("invalid snapshot acceptance")
			}
			if valid && refs == nil {
				t.Fatal("complete empty capture must not be a pending nil capture")
			}
		})
	}
}

func TestRevocationAcknowledgementAndBounds(t *testing.T) {
	subject := "00000000-0000-0000-0000-000000000001"
	refs := []Ref{{"opaque~id", true}}
	for _, reply := range []string{`{"removed":1,"missing":0}`, `{"removed":0,"missing":1}`,
		`{"removed":0,"missing":0}`, `{"removed":2,"missing":-1}`, `{"removed":1}`, `{"missing":1}`, `{"removed":1,"missing":0,"extra":true}`} {
		c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Sessions []Ref `json:"sessions"`
			}
			if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Sessions) != 1 || body.Sessions[0] != refs[0] {
				t.Error("capture changed in transit")
			}
			fmt.Fprint(w, reply)
		})
		err := c.Revoke(context.Background(), subject, refs)
		if (err == nil) != (reply == `{"removed":1,"missing":0}` || reply == `{"removed":0,"missing":1}`) {
			t.Fatal("invalid acknowledgement accepted")
		}
	}
	var calls atomic.Int32
	c := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, `{}`) })
	for _, bad := range [][]Ref{nil, {{"", false}}, {{"bad\nid", false}}, {{"id", true}, {"id", true}}, make([]Ref, 101)} {
		if c.Revoke(context.Background(), subject, bad) == nil {
			t.Fatal("invalid batch accepted")
		}
	}
	if c.Revoke(context.Background(), "../another-subject", refs) == nil || calls.Load() != 0 {
		t.Fatal("invalid input reached identity server")
	}
}

func TestSessionTransportCannotLeakCredentials(t *testing.T) {
	var received atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
	defer target.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	provider := func(context.Context) (string, error) { return "private-canary", nil }
	for _, endpoint := range []string{s.URL + "/realms/rentacompa/rac-sessions", "https://user:secret@host/realms/rentacompa/rac-sessions", "https://host/wrong", "https://host/realms/rentacompa/rac-sessions?token=x"} {
		if _, err := NewClient(endpoint, provider, false); err == nil {
			t.Fatal("unsafe identity configuration")
		}
	}
	c, _ := NewClient(s.URL+"/realms/rentacompa/rac-sessions", provider, true)
	if !errors.Is(c.Check(context.Background()), ErrUnavailable) || received.Load() != 0 {
		t.Fatal("credential-bearing redirect followed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c.Check(ctx) == nil {
		t.Fatal("cancelled request accepted")
	}
	unknown := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"schema_version":2}`) })
	if unknown.Check(context.Background()) == nil {
		t.Fatal("unknown provider contract accepted")
	}
}
