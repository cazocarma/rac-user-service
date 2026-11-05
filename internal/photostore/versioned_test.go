package photostore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVersionedMediaPinsProviderVersionAndPreservesExistingObjects(t *testing.T) {
	const key = "11111111111111111111111111111111.jpg"
	const version = "opaque+/=version-1"
	data := []byte{0xff, 0xd8, 0xff, 0x01}
	created := false
	gets := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/media/"+key {
			t.Errorf("unbounded media key %s", r.URL.Path)
			w.WriteHeader(400)
			return
		}
		if r.Method == "PUT" {
			if r.Header.Get("If-None-Match") != "*" || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Content-Type") != "image/jpeg" {
				t.Error("unsafe media creation")
			}
			body, _ := io.ReadAll(r.Body)
			if !bytes.Equal(body, data) {
				t.Error("source bytes changed")
			}
			if created {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(412)
				w.Write([]byte(`<Error><Code>PreconditionFailed</Code></Error>`))
				return
			}
			created = true
			w.Header().Set("x-amz-version-id", version)
			return
		}
		if r.Method != "GET" {
			t.Errorf("unexpected media mutation %s", r.Method)
			w.WriteHeader(400)
			return
		}
		gets++
		if gets == 1 && r.URL.Query().Get("versionId") != "" {
			t.Error("recovery unexpectedly pinned a guessed version")
		}
		if gets == 2 && r.URL.Query().Get("versionId") != version {
			t.Error("read did not pin opaque provider version")
		}
		w.Header().Set("x-amz-version-id", version)
		w.Header().Set("ETag", `"not-a-content-digest"`)
		w.Write(data)
	}))
	defer server.Close()
	store, err := NewVersionedS3(server.URL, "us-east-1", "media", "synthetic-only", "synthetic-secret")
	if err != nil {
		t.Fatal(err)
	}
	actual, err := store.Create(context.Background(), key, data)
	if err != nil || actual != version {
		t.Fatal("provider version not captured", actual, err)
	}
	if _, err := store.Create(context.Background(), key, data); !errors.Is(err, ErrExists) {
		t.Fatal("create overwrote existing version", err)
	}
	object, err := store.Current(context.Background(), key)
	if err != nil || object.VersionID() != version || !bytes.Equal(object.Bytes(), data) {
		t.Fatal("recovery did not return exact object/version", err)
	}
	copy := object.Bytes()
	copy[0] = 0
	if !bytes.Equal(object.Bytes(), data) {
		t.Fatal("returned bytes mutated captured read")
	}
	actualBytes, err := store.Version(context.Background(), key, version)
	if err != nil || !bytes.Equal(actualBytes, data) || gets != 2 {
		t.Fatal("explicit version read failed", err, gets)
	}
}

func TestVersionedMediaRejectsUnversionedWrongAndOversizeReads(t *testing.T) {
	const key = "11111111111111111111111111111111.jpg"
	for _, tc := range []struct {
		name, returned string
		size           int
	}{
		{"missing", "", 4}, {"null", "null", 4}, {"mismatched", "other-version", 4}, {"oversize", "expected-version", MaxStoredBytes + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if tc.returned != "" {
					w.Header().Set("x-amz-version-id", tc.returned)
				}
				if r.Method == "GET" {
					w.Write(bytes.Repeat([]byte{0x01}, tc.size))
				}
			}))
			defer server.Close()
			store, err := NewVersionedS3(server.URL, "us-east-1", "media", "synthetic-only", "synthetic-secret")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Version(context.Background(), key, "expected-version"); err == nil {
				t.Fatal("unusable version accepted")
			}
			if tc.name == "missing" || tc.name == "null" {
				if _, err := store.Current(context.Background(), key); !errors.Is(err, ErrVersionUnavailable) {
					t.Fatal("unversioned current object accepted", err)
				}
				if _, err := store.Create(context.Background(), key, []byte{1}); !errors.Is(err, ErrVersionUnavailable) {
					t.Fatal("unversioned creation accepted", err)
				}
			}
			before := calls
			for _, invalid := range []string{"", "null", "bad\x00id", strings.Repeat("a", 2049), " padded "} {
				if _, err := store.Version(context.Background(), key, invalid); !errors.Is(err, ErrVersionUnavailable) {
					t.Fatal("invalid version sent", err)
				}
			}
			if calls != before {
				t.Fatal("invalid versions reached network")
			}
		})
	}
}
