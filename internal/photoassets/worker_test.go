package photoassets

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cazocarma/rac-user-service/internal/photostore"
)

type workQueueFixture struct {
	claim                 *Attempt
	claimErr, completeErr error
	receipts              []Artifact
	completeHook          func(Attempt, Release, Artifact) error
}

func (q *workQueueFixture) Claim(context.Context, Release) (*Attempt, error) {
	return q.claim, q.claimErr
}
func (q *workQueueFixture) Complete(_ context.Context, a Attempt, r Release, result Artifact) error {
	if q.completeHook != nil {
		return q.completeHook(a, r, result)
	}
	q.receipts = append(q.receipts, result)
	return q.completeErr
}

type artifactFixture struct {
	data           []byte
	putErr, getErr error
	key            string
	putHook        func()
}

func (s *artifactFixture) Put(_ context.Context, key string, raw []byte) error {
	s.key = key
	if s.putHook != nil {
		s.putHook()
	}
	if s.putErr == nil {
		s.data = slices.Clone(raw)
	}
	return s.putErr
}
func (s *artifactFixture) Get(_ context.Context, key string) ([]byte, error) {
	if key != s.key {
		return nil, errors.New("wrong artifact key")
	}
	return slices.Clone(s.data), s.getErr
}

func workerFixture(t *testing.T, q WorkQueue, staging ArtifactStore) (*Worker, Upload) {
	t.Helper()
	upload := imageFixture(t, "benign")
	processor, err := NewProcessor("fixture-pipeline-1", ocrFunc(func(context.Context, []byte) (OCRResult, error) {
		return ocrFixture("CINE Y MUSEOS"), nil
	}), engineFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	release := Release{Pipeline: "fixture-pipeline-1", Commit: strings.Repeat("a", 40), ImageDigest: "sha256:" + strings.Repeat("b", 64)}
	w, err := NewWorker(q, readerFunc(func(context.Context, string) ([]byte, error) { return upload.Bytes(), nil }), staging, processor, release)
	if err != nil {
		t.Fatal(err)
	}
	return w, upload
}

func TestWorkerVerifiesStoredArtifactBeforeAcknowledging(t *testing.T) {
	for _, kind := range []string{"new", "identical existing", "corrupt existing", "uncertain put", "failed read", "lost completion ack", "cancelled put"} {
		t.Run(kind, func(t *testing.T) {
			q := &workQueueFixture{}
			store := &artifactFixture{}
			w, upload := workerFixture(t, q, store)
			q.claim = &Attempt{ID: strings.Repeat("1", 32), Source: upload.Source()}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var expected error
			switch kind {
			case "identical existing":
				p, err := w.processor.Process(ctx, upload.Source(), w.source)
				if err != nil {
					t.Fatal(err)
				}
				store.data = p.Image()
				store.putErr = photostore.ErrExists
			case "corrupt existing":
				store.data = []byte("corrupt")
				store.putErr = photostore.ErrExists
				expected = ErrIntegrity
			case "uncertain put":
				store.putErr = errors.New("lost s3 ack")
				expected = ErrStorage
			case "failed read":
				store.getErr = errors.New("read unavailable")
				expected = ErrStorage
			case "lost completion ack":
				q.completeErr = errors.New("lost database ack")
				expected = q.completeErr
			case "cancelled put":
				store.putHook = cancel
				expected = context.Canceled
			}
			claimed, err := w.RunOnce(ctx)
			if !claimed || !errors.Is(err, expected) {
				t.Fatalf("claimed=%v err=%v expected=%v", claimed, err, expected)
			}
			wantReceipt := expected == nil || kind == "lost completion ack"
			if (len(q.receipts) == 1) != wantReceipt {
				t.Fatal("acknowledged an unverified or cancelled artifact")
			}
			if wantReceipt {
				a := q.receipts[0]
				if a.ObjectKey() != q.claim.ObjectKey() || a.Size() != len(store.data) || a.Disposition() != NeedsReview || a.DigestHex() == "" {
					t.Fatal("invalid receipt")
				}
				proof := a.Assessment()
				proof[0] ^= 0xff
				if slices.Equal(proof, a.Assessment()) {
					t.Fatal("private assessment is mutable")
				}
			}
		})
	}
}

func TestWorkerIdleAndInvalidClaim(t *testing.T) {
	q := &workQueueFixture{}
	w, upload := workerFixture(t, q, &artifactFixture{})
	if claimed, err := w.RunOnce(context.Background()); claimed || err != nil {
		t.Fatal("idle queue became work", err)
	}
	for _, id := range []string{"../escape", strings.Repeat("0", 32), ""} {
		q.claim = &Attempt{ID: id, Source: upload.Source()}
		if _, err := w.RunOnce(context.Background()); !errors.Is(err, ErrInvalid) {
			t.Fatal("unsafe artifact key accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if claimed, err := w.RunOnce(ctx); claimed || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled worker claimed work")
	}
}

func TestWorkerProcessingFailureCannotAcknowledge(t *testing.T) {
	q := &workQueueFixture{}
	store := &artifactFixture{}
	w, upload := workerFixture(t, q, store)
	q.claim = &Attempt{ID: strings.Repeat("1", 32), Source: upload.Source()}
	w.processor.ocr = ocrFunc(func(context.Context, []byte) (OCRResult, error) { return OCRResult{}, errors.New("OCR failed") })
	if claimed, err := w.RunOnce(context.Background()); !claimed || !errors.Is(err, ErrProcessing) {
		t.Fatal("processing failure was swallowed", err)
	}
	if store.key != "" || len(q.receipts) != 0 {
		t.Fatal("processing failure produced an artifact or acknowledgment")
	}
}

func TestWorkerRejectsUnboundRelease(t *testing.T) {
	w, _ := workerFixture(t, &workQueueFixture{}, &artifactFixture{})
	for _, r := range []Release{
		{},
		{Pipeline: w.release.Pipeline, Commit: "main", ImageDigest: w.release.ImageDigest},
		{Pipeline: w.release.Pipeline, Commit: w.release.Commit, ImageDigest: "worker:latest"},
		{Pipeline: "another-pipeline", Commit: w.release.Commit, ImageDigest: w.release.ImageDigest},
	} {
		if _, err := NewWorker(w.queue, w.source, w.staging, w.processor, r); !errors.Is(err, ErrInvalid) {
			t.Fatal("unbound release accepted", err)
		}
	}
}

// Deterministically model a lease expiring while worker A is in OCR. Worker B
// claims a NEW object key and finishes. The durable adapter must enforce the
// same fence atomically; these tests only prove the runner respects its result.
func TestWorkerLeaseLossDoesNotOverwriteNewAttempt(t *testing.T) {
	entered, resume := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	active := strings.Repeat("2", 32)
	completed := ""
	q := &workQueueFixture{}
	storeA, storeB := &artifactFixture{}, &artifactFixture{}
	a, upload := workerFixture(t, q, storeA)
	b, _ := workerFixture(t, q, storeB)
	claimA := Attempt{ID: strings.Repeat("1", 32), Source: upload.Source()}
	claimB := Attempt{ID: active, Source: upload.Source()}
	a.queue = &workQueueFixture{claim: &claimA, completeHook: func(at Attempt, _ Release, _ Artifact) error {
		mu.Lock()
		defer mu.Unlock()
		if at.ID != active {
			return ErrClaimLost
		}
		completed = at.ID
		return nil
	}}
	b.queue = &workQueueFixture{claim: &claimB, completeHook: func(at Attempt, _ Release, _ Artifact) error {
		mu.Lock()
		defer mu.Unlock()
		if at.ID != active {
			return ErrClaimLost
		}
		completed = at.ID
		return nil
	}}
	// Both attempts refer to the very same immutable source.
	b.source = a.source
	a.processor.ocr = ocrFunc(func(context.Context, []byte) (OCRResult, error) {
		close(entered)
		<-resume
		return ocrFixture("CINE"), nil
	})
	done := make(chan error, 1)
	go func() { _, err := a.RunOnce(context.Background()); done <- err }()
	<-entered
	if _, err := b.RunOnce(context.Background()); err != nil {
		close(resume)
		t.Fatal(err)
	}
	close(resume)
	if err := <-done; !errors.Is(err, ErrClaimLost) {
		t.Fatal("stale worker completion accepted", err)
	}
	if storeA.key == storeB.key || completed != claimB.ID {
		t.Fatal("stale worker overwrote the newer artifact")
	}
}
