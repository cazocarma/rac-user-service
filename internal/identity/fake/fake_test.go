package fake

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cazocarma/rac-user-service/internal/identity"
)

var secret = bytes.Repeat([]byte("s"), 32)

func adult(value bool) *bool { return &value }

func TestFakeRefusesNonDevelopmentEnvironments(t *testing.T) {
	for _, environment := range []string{"", "qa", "prd", "production", "DEV"} {
		if _, err := New(environment, secret, "http://localhost"); err == nil {
			t.Fatalf("fake accepted environment %q", environment)
		}
	}
	if _, err := New("dev", secret[:31], "http://localhost"); err == nil {
		t.Fatal("short secret accepted")
	}
	if _, err := New("dev", secret, "localhost"); err == nil {
		t.Fatal("relative base URL accepted")
	}
	for _, environment := range []string{"dev", "test"} {
		if _, err := New(environment, secret, "http://localhost"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSessionReferencesAreOpaque(t *testing.T) {
	p, _ := New("test", secret, "http://localhost:8080/")
	first, err := p.CreateSession(context.Background(), "user-subject", identity.ClientBooking)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := p.CreateSession(context.Background(), "user-subject", identity.ClientBooking)
	if first.ProviderRef == second.ProviderRef || strings.Contains(first.ProviderRef+first.URL, "user-subject") {
		t.Fatal("session references must be fresh and unrelated to the RAC subject")
	}
	if !strings.HasPrefix(first.URL, "http://localhost:8080/identity/fake?ref=") {
		t.Fatal(first.URL)
	}
	if _, err := p.CreateSession(context.Background(), "", "admin"); err == nil {
		t.Fatal("unknown purpose accepted")
	}
}

func TestWebhookAuthenticatesOriginalBytesWithinWindow(t *testing.T) {
	p, _ := New("test", secret, "http://localhost")
	now := time.Unix(1_800_000_000, 0)
	p.now = func() time.Time { return now }
	body := Body("evt_00000001", "fake_00000001", identity.Approved, adult(true), "CL", bytes.Repeat([]byte{9}, 16))
	request := func(payload []byte, signature string) (identity.Result, error) {
		r := httptest.NewRequest("POST", "/api/user/identity/webhook", bytes.NewReader(payload))
		if signature != "" {
			r.Header.Set(SignatureHeader, signature)
		}
		return p.VerifyWebhook(r)
	}
	result, err := request(body, p.Sign(body, now))
	if err != nil || result.Outcome != identity.Approved || *result.Adult != true || result.DocumentCountry != "CL" {
		t.Fatal(result, err)
	}
	tampered := bytes.Replace(body, []byte(`"CL"`), []byte(`"AR"`), 1)
	other, _ := New("test", bytes.Repeat([]byte("o"), 32), "http://localhost")
	for name, attempt := range map[string]func() (identity.Result, error){
		"missing signature": func() (identity.Result, error) { return request(body, "") },
		"tampered body":     func() (identity.Result, error) { return request(tampered, p.Sign(body, now)) },
		"other secret":      func() (identity.Result, error) { return request(body, other.Sign(body, now)) },
		"stale":             func() (identity.Result, error) { return request(body, p.Sign(body, now.Add(-6*time.Minute))) },
		"future":            func() (identity.Result, error) { return request(body, p.Sign(body, now.Add(6*time.Minute))) },
		"bad header":        func() (identity.Result, error) { return request(body, "t=1,v1=zz") },
		"extra part":        func() (identity.Result, error) { return request(body, p.Sign(body, now)+",v0=00") },
		"unknown field": func() (identity.Result, error) {
			extra := bytes.Replace(body, []byte(`{`), []byte(`{"user_id":"x",`), 1)
			return request(extra, p.Sign(extra, now))
		},
		"trailing json": func() (identity.Result, error) {
			twice := append(append([]byte{}, body...), body...)
			return request(twice, p.Sign(twice, now))
		},
		"oversized": func() (identity.Result, error) {
			huge := append(append([]byte{}, body...), bytes.Repeat([]byte(" "), maxBody)...)
			return request(huge, p.Sign(huge, now))
		},
		"invalid result": func() (identity.Result, error) {
			minor := Body("evt_00000001", "fake_00000001", identity.Approved, adult(true), "", nil)
			return request(minor, p.Sign(minor, now))
		},
	} {
		if _, err := attempt(); err != identity.ErrInvalidWebhook {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
