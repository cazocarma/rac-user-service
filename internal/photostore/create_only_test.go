package photostore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"
)

func TestS3ConditionalCreation(t *testing.T) {
	var stored []byte
	var mutex sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		if r.Method != "PUT" || r.Header.Get("If-None-Match") != "*" {
			t.Error("photo write was not conditional")
			w.WriteHeader(400)
			return
		}
		if stored != nil {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(412)
			w.Write([]byte(`<Error><Code>PreconditionFailed</Code></Error>`))
			return
		}
		stored, _ = io.ReadAll(r.Body)
	}))
	defer server.Close()
	store, err := NewS3(server.URL, "us-east-1", "photos", "fixture-key", "fixture-secret")
	if err != nil {
		t.Fatal(err)
	}
	key := "11111111111111111111111111111111.jpg"
	if err = store.Put(context.Background(), key, []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err = store.Put(context.Background(), key, []byte("replacement")); !errors.Is(err, ErrExists) {
		t.Fatal("existing object not classified", err)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if !bytes.Equal(stored, []byte("original")) {
		t.Fatal("existing object changed")
	}
}

// This proof only runs on the runner's disposable server, never the configured
// development endpoint or real credentials. A skip does not prove S3 semantics.
func TestS3CreateOnlyIntegration(t *testing.T) {
	endpoint := os.Getenv("RAC_PHOTO_CREATE_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires disposable RustFS laboratory")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.Hostname() != "photo-storage-fixture" || u.Port() != "9000" {
		t.Fatal("refusing non-disposable object store")
	}
	store, err := NewS3(endpoint, "us-east-1", os.Getenv("PROFILE_S3_BUCKET"), os.Getenv("PROFILE_S3_ACCESS_KEY"), os.Getenv("PROFILE_S3_SECRET_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	key := func() string {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(id[:]) + ".jpg"
	}
	first := key()
	defer store.Delete(ctx, first)
	if err := store.Put(ctx, first, []byte("first immutable payload")); err != nil {
		t.Fatal("initial create failed", err)
	}
	if err := store.Put(ctx, first, []byte("second payload")); !errors.Is(err, ErrExists) {
		t.Fatal("existing object replaced or misclassified", err)
	}
	raw, err := store.Get(ctx, first)
	if err != nil || string(raw) != "first immutable payload" {
		t.Fatal("conditional create did not preserve bytes", err)
	}
	contested := key()
	defer store.Delete(ctx, contested)
	type result struct {
		payload string
		err     error
	}
	outcomes := make(chan result, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, payload := range []string{"candidate A", "candidate B"} {
		wg.Add(1)
		go func(payload string) {
			defer wg.Done()
			<-start
			outcomes <- result{payload, store.Put(ctx, contested, []byte(payload))}
		}(payload)
	}
	close(start)
	wg.Wait()
	close(outcomes)
	winner := ""
	success, conflict := 0, 0
	for result := range outcomes {
		if result.err == nil {
			success++
			winner = result.payload
		} else if errors.Is(result.err, ErrExists) || errors.Is(result.err, ErrConflict) {
			conflict++
		} else {
			t.Fatal("unexpected conditional error", result.err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("concurrent writes did not have exactly one winner", success, conflict)
	}
	raw, err = store.Get(ctx, contested)
	if err != nil || string(raw) != winner {
		t.Fatal("stored bytes differ from acknowledged winner", err)
	}
}
