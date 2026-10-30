// Package fake simulates an identity provider for DEV and tests. It refuses
// construction in any other environment, and its approvals never back a real
// public badge (the provider name "fake" stays on every record).
package fake

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cazocarma/rac-user-service/internal/identity"
)

const (
	SignatureHeader = "X-RAC-Identity-Signature"
	maxBody         = 16 << 10
	tolerance       = 5 * time.Minute
)

type Provider struct {
	secret  []byte
	baseURL string
	now     func() time.Time
}

// New accepts only RAC_ENV dev or test and a secret of at least 32 bytes.
func New(environment string, secret []byte, baseURL string) (*Provider, error) {
	if environment != "dev" && environment != "test" {
		return nil, errors.New("fake identity provider is restricted to dev and test")
	}
	if len(secret) < 32 {
		return nil, errors.New("fake identity webhook secret requires at least 32 bytes")
	}
	base, err := url.Parse(baseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, errors.New("fake identity provider requires an explicit base URL")
	}
	return &Provider{secret: append([]byte(nil), secret...), baseURL: strings.TrimRight(baseURL, "/"), now: time.Now}, nil
}

func (p *Provider) Name() string { return "fake" }

// CreateSession returns an opaque reference unrelated to the RAC user id.
func (p *Provider) CreateSession(_ context.Context, _ string, purpose identity.Purpose) (identity.Session, error) {
	if !purpose.Valid() {
		return identity.Session{}, identity.ErrInvalidResult
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return identity.Session{}, identity.ErrUnavailable
	}
	ref := "fake_" + hex.EncodeToString(random)
	return identity.Session{ProviderRef: ref, URL: p.baseURL + "/identity/fake?ref=" + ref}, nil
}

// Sign produces the header value for body at time at. Tests and the DEV
// simulator use it; nothing else holds the secret.
func (p *Provider) Sign(body []byte, at time.Time) string {
	timestamp := strconv.FormatInt(at.Unix(), 10)
	return "t=" + timestamp + ",v1=" + hex.EncodeToString(p.mac(timestamp, body))
}

func (p *Provider) mac(timestamp string, body []byte) []byte {
	mac := hmac.New(sha256.New, p.secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return mac.Sum(nil)
}

type payload struct {
	EventID         string `json:"event_id"`
	ProviderRef     string `json:"provider_ref"`
	Outcome         string `json:"outcome"`
	Adult           *bool  `json:"adult"`
	DocumentCountry string `json:"document_country"`
	IdentityKey     string `json:"identity_key"`
}

// VerifyWebhook authenticates the original bytes before decoding anything.
func (p *Provider) VerifyWebhook(r *http.Request) (identity.Result, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) == 0 || len(body) > maxBody {
		return identity.Result{}, identity.ErrInvalidWebhook
	}
	timestamp, signature, ok := parseHeader(r.Header.Get(SignatureHeader))
	if !ok {
		return identity.Result{}, identity.ErrInvalidWebhook
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return identity.Result{}, identity.ErrInvalidWebhook
	}
	if skew := p.now().Sub(time.Unix(seconds, 0)); skew > tolerance || skew < -tolerance {
		return identity.Result{}, identity.ErrInvalidWebhook
	}
	if !hmac.Equal(signature, p.mac(timestamp, body)) {
		return identity.Result{}, identity.ErrInvalidWebhook
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var in payload
	if decoder.Decode(&in) != nil || decoder.More() {
		return identity.Result{}, identity.ErrInvalidWebhook
	}
	var key []byte
	if in.IdentityKey != "" {
		if key, err = base64.RawURLEncoding.DecodeString(in.IdentityKey); err != nil {
			return identity.Result{}, identity.ErrInvalidWebhook
		}
	}
	result := identity.Result{EventID: in.EventID, ProviderRef: in.ProviderRef, Outcome: identity.Status(in.Outcome),
		Adult: in.Adult, DocumentCountry: in.DocumentCountry, IdentityKey: key}
	if result.Validate() != nil {
		return identity.Result{}, identity.ErrInvalidWebhook
	}
	return result, nil
}

func parseHeader(value string) (string, []byte, bool) {
	var timestamp string
	var signature []byte
	for _, part := range strings.Split(value, ",") {
		name, raw, found := strings.Cut(part, "=")
		if !found {
			return "", nil, false
		}
		switch name {
		case "t":
			timestamp = raw
		case "v1":
			decoded, err := hex.DecodeString(raw)
			if err != nil || len(decoded) != sha256.Size {
				return "", nil, false
			}
			signature = decoded
		default:
			return "", nil, false
		}
	}
	return timestamp, signature, timestamp != "" && signature != nil
}

// DeleteSubjectData has nothing to erase: the fake keeps no subject data.
func (p *Provider) DeleteSubjectData(context.Context, string) error { return nil }

var _ identity.Provider = (*Provider)(nil)

// Body builds a simulated webhook body; it exists for DEV tooling and tests.
func Body(eventID, providerRef string, outcome identity.Status, adult *bool, country string, identityKey []byte) []byte {
	encoded, _ := json.Marshal(payload{EventID: eventID, ProviderRef: providerRef, Outcome: string(outcome),
		Adult: adult, DocumentCountry: country, IdentityKey: base64.RawURLEncoding.EncodeToString(identityKey)})
	return encoded
}
