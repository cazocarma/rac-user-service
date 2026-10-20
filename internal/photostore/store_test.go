package photostore

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalSafety(t *testing.T) {
	s := Local{Directory: t.TempDir()}
	ctx := context.Background()
	key := strings.Repeat("a", 32) + ".jpg"
	if err := s.Put(ctx, "../escape", []byte("x")); err == nil {
		t.Fatal("unsafe key accepted")
	}
	if err := s.Put(ctx, key, []byte("image")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, key, []byte("overwrite")); err == nil {
		t.Fatal("existing photo overwritten")
	}
	raw, err := s.Get(ctx, key)
	if err != nil || !bytes.Equal(raw, []byte("image")) {
		t.Fatal("content changed", err)
	}
	if err = s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err = s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing photo not classified")
	}
}
func TestS3FailureClassification(t *testing.T) {
	key := strings.Repeat("a", 32) + ".jpg"
	for _, tc := range []struct {
		name, body string
		status     int
		missing    bool
	}{
		{"missing", "<Error><Code>NoSuchKey</Code></Error>", 404, true},
		{"denied", "<Error><Code>AccessDenied</Code></Error>", 403, false},
		{"unavailable", "<Error><Code>ServiceUnavailable</Code></Error>", 503, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/photos/"+key || !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
					t.Error("unsigned or incorrect S3 request")
				}
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			s, err := NewS3(server.URL, "us-east-1", "photos", "test-key", "test-secret")
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.Get(context.Background(), key)
			if err == nil || errors.Is(err, ErrNotFound) != tc.missing {
				t.Fatal("incorrect failure classification", err)
			}
		})
	}
}
func TestS3BoundedReadAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(make([]byte, MaxStoredBytes+1)) }))
	defer server.Close()
	s, err := NewS3(server.URL, "us-east-1", "photos", "key", "secret")
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("a", 32) + ".jpg"
	if _, err = s.Get(context.Background(), key); err == nil {
		t.Fatal("unbounded object read")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = s.Put(ctx, key, []byte("x")); err == nil {
		t.Fatal("cancelled write succeeded")
	}
	if _, err = NewS3("http://user:secret@storage", "us-east-1", "photos", "key", "secret"); err == nil {
		t.Fatal("URL credentials accepted")
	}
	t.Setenv("PROFILE_PHOTO_STORAGE", "unknown")
	if _, err = FromEnvironment(); err == nil {
		t.Fatal("invalid driver silently fell back")
	}
}
