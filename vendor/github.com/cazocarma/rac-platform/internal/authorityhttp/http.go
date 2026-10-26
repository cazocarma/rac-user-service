// Package authorityhttp centralizes bounded JSON exchanges for internal owners.
package authorityhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

var ErrUnavailable = errors.New("authority unavailable")

func New(endpoint string, allowDEVHTTP bool) (*http.Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && !(allowDEVHTTP && u.Scheme == "http")) {
		return nil, ErrUnavailable
	}
	return &http.Client{Timeout: 1500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func Decode(reader io.Reader, value any) error {
	d := json.NewDecoder(reader)
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrUnavailable
	}
	return nil
}
func Exchange(ctx context.Context, client *http.Client, endpoint string, token func(context.Context) (string, error), input any, limit int, result any) error {
	if ctx == nil || client == nil || token == nil || limit <= 0 {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	credential, err := token(ctx)
	if err != nil || credential == "" {
		return ErrUnavailable
	}
	body, err := json.Marshal(input)
	if err != nil {
		return ErrUnavailable
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return ErrUnavailable
	}
	r.Header.Set("Authorization", "Bearer "+credential)
	r.Header.Set("Content-Type", "application/json")
	reply, err := client.Do(r)
	if err != nil {
		return ErrUnavailable
	}
	defer reply.Body.Close()
	if reply.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(reply.Body, int64(limit)+1))
	if err != nil || len(data) > limit || Decode(bytes.NewReader(data), result) != nil {
		return ErrUnavailable
	}
	return nil
}
