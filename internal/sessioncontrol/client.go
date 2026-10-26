// Package sessioncontrol owns the durable identity effects of account standing.
package sessioncontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cazocarma/rac-platform/standing"
)

var ErrUnavailable = errors.New("session control unavailable")
var ErrClaimLost = errors.New("session effect claim lost")

const MaxSnapshot = 4096
const BatchSize = 32 // Even 256-byte opaque identifiers fit the 16 KiB request.

type Ref struct {
	ID      string `json:"id"`
	Offline bool   `json:"offline"`
}

type Gateway interface {
	Check(context.Context) error
	Snapshot(context.Context, string) ([]Ref, error)
	Revoke(context.Context, string, []Ref) error
}

type Client struct {
	endpoint string
	token    func(context.Context) (string, error)
	http     *http.Client
}

func NewClient(endpoint string, token func(context.Context) (string, error), allowDEVHTTP bool) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" ||
		strings.TrimSuffix(u.Path, "/") != "/realms/rentacompa/rac-sessions" || token == nil ||
		(u.Scheme != "https" && !(allowDEVHTTP && u.Scheme == "http")) {
		return nil, ErrUnavailable
	}
	return &Client{endpoint: strings.TrimSuffix(endpoint, "/"), token: token, http: &http.Client{
		Timeout:       1500 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func validSubject(subject string) bool { return standing.ValidAccountID(subject) }

func validRefs(refs []Ref) bool {
	if len(refs) > MaxSnapshot {
		return false
	}
	seen := make(map[Ref]bool, len(refs))
	for _, ref := range refs {
		if ref.ID == "" || len(ref.ID) > 256 || seen[ref] {
			return false
		}
		for _, char := range ref.ID {
			if char <= 32 || char > 126 {
				return false
			}
		}
		seen[ref] = true
	}
	return true
}

func decode(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return ErrUnavailable
	}
	return nil
}

func (c *Client) exchange(ctx context.Context, method, path string, input, output any) error {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	token, err := c.token(ctx)
	if err != nil || token == "" || ctx.Err() != nil {
		return ErrUnavailable
	}
	var body []byte
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil || len(body) > 16384 {
			return ErrUnavailable
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	reply, err := c.http.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer reply.Body.Close()
	if reply.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	// 4096 bounded opaque IDs, including worst-case JSON escaping.
	const limit = 3 << 20
	raw, err := io.ReadAll(io.LimitReader(reply.Body, limit+1))
	if err != nil || len(raw) > limit || decode(raw, output) != nil {
		return ErrUnavailable
	}
	return nil
}

func (c *Client) Check(ctx context.Context) error {
	var status struct {
		Version int `json:"schema_version"`
	}
	if c.exchange(ctx, http.MethodGet, "/status", nil, &status) != nil || status.Version != 1 {
		return ErrUnavailable
	}
	return nil
}

func (c *Client) Snapshot(ctx context.Context, subject string) ([]Ref, error) {
	if !validSubject(subject) {
		return nil, ErrUnavailable
	}
	var wire struct {
		Complete *bool `json:"complete"`
		Sessions *[]struct {
			ID      string `json:"id"`
			Offline *bool  `json:"offline"`
		} `json:"sessions"`
	}
	if c.exchange(ctx, http.MethodGet, "/users/"+subject+"/sessions", nil, &wire) != nil ||
		wire.Complete == nil || !*wire.Complete || wire.Sessions == nil || len(*wire.Sessions) > MaxSnapshot {
		return nil, ErrUnavailable
	}
	refs := make([]Ref, 0, len(*wire.Sessions))
	for _, ref := range *wire.Sessions {
		if ref.Offline == nil {
			return nil, ErrUnavailable
		}
		refs = append(refs, Ref{ref.ID, *ref.Offline})
	}
	if !validRefs(refs) {
		return nil, ErrUnavailable
	}
	return refs, nil
}

func (c *Client) Revoke(ctx context.Context, subject string, refs []Ref) error {
	if !validSubject(subject) || len(refs) == 0 || len(refs) > 100 || !validRefs(refs) {
		return ErrUnavailable
	}
	var result struct {
		Removed *int `json:"removed"`
		Missing *int `json:"missing"`
	}
	if c.exchange(ctx, http.MethodPost, "/users/"+subject+"/sessions/revoke", struct {
		Sessions []Ref `json:"sessions"`
	}{refs}, &result) != nil ||
		result.Removed == nil || result.Missing == nil || *result.Removed < 0 || *result.Missing < 0 ||
		*result.Removed > len(refs) || *result.Missing != len(refs)-*result.Removed {
		return ErrUnavailable
	}
	return nil
}
