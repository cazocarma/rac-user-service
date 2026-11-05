// Package secretfile loads explicitly mounted secrets; it never falls back to
// plaintext environment values or prints paths, contents or underlying errors.
package secretfile

import (
	"errors"
	"io"
	"os"
	"strings"
)

func ReadEnvironment(name string) (string, error) {
	path := os.Getenv(name + "_FILE")
	if path == "" {
		return "", errors.New("missing secret file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("secret file unavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) > 8192 {
		return "", errors.New("invalid secret file")
	}
	value := strings.TrimRight(string(raw), "\r\n")
	if value == "" {
		return "", errors.New("empty secret file")
	}
	return value, nil
}
