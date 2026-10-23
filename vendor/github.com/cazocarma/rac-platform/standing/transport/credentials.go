package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cazocarma/rac-platform/standing"
)

// CredentialsToken reads a mounted secret file only when refreshing a short
// lived client-credentials token. No refresh token is requested or retained.
// The identity provisioner must restrict this client to the standing audience
// and standing reader role; a commercial user/admin token is not a substitute.
func CredentialsToken(endpoint, clientID, secretFile string, allowDEVHTTP bool) (TokenProvider, error) {
	if clientID == "" || secretFile == "" {
		return nil, standing.ErrUnavailable
	}
	// Reuse endpoint validation and the no-redirect transport policy.
	validated, err := NewClient(endpoint, func(context.Context) (string, error) { return "", nil }, allowDEVHTTP)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	var cached string
	var until time.Time
	return func(ctx context.Context) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
		mu.Lock()
		defer mu.Unlock()
		if ctx.Err() != nil {
			return "", standing.ErrUnavailable
		}
		if cached != "" && time.Now().Before(until) {
			return cached, nil
		}
		file, err := os.Open(secretFile)
		if err != nil {
			return "", standing.ErrUnavailable
		}
		secret, err := io.ReadAll(io.LimitReader(file, 4097))
		file.Close()
		if err != nil || len(secret) > 4096 || strings.TrimSpace(string(secret)) == "" {
			return "", standing.ErrUnavailable
		}
		form := url.Values{"grant_type": {"client_credentials"}}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, validated.endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return "", standing.ErrUnavailable
		}
		// RFC 6749 section 2.3.1: encode each credential before HTTP Basic.
		r.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(strings.TrimSpace(string(secret))))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		started := time.Now()
		reply, err := validated.client.Do(r)
		if err != nil {
			return "", standing.ErrUnavailable
		}
		defer reply.Body.Close()
		if reply.StatusCode != http.StatusOK {
			return "", standing.ErrUnavailable
		}
		data, err := io.ReadAll(io.LimitReader(reply.Body, maxBody+1))
		if err != nil || len(data) > maxBody {
			return "", standing.ErrUnavailable
		}
		var result struct {
			Token   string `json:"access_token"`
			Type    string `json:"token_type"`
			Expires int    `json:"expires_in"`
		}
		d := json.NewDecoder(bytes.NewReader(data))
		if d.Decode(&result) != nil || d.Decode(new(any)) != io.EOF || result.Token == "" || !strings.EqualFold(result.Type, "Bearer") || result.Expires <= 5 || result.Expires > 300 {
			return "", standing.ErrUnavailable
		}
		expiry := started.Add(time.Duration(result.Expires)*time.Second - 5*time.Second)
		if !time.Now().Before(expiry) {
			return "", standing.ErrUnavailable
		}
		cached, until = result.Token, expiry
		return cached, nil
	}, nil
}
