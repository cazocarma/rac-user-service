package tseffects

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lib/pq"
)

type fakeStore struct {
	err   error
	calls int
}

func (f *fakeStore) Apply(context.Context, string, []byte) error {
	f.calls++
	return f.err
}

const id = "aaaaaaaa-1111-4111-8111-11111111111b"

func TestEnvelopeIsValidatedBeforeTheStore(t *testing.T) {
	body := []byte(`{"action_id":"x"}`)
	for _, c := range []struct {
		body             []byte
		id, typ, content string
	}{
		{body, id, "ts.action.other.v1", "application/json"},
		{body, id, EventType, "text/plain"},
		{body, "not-an-id", EventType, "application/json"},
		{body, strings.ToUpper(id), EventType, "application/json"},
		{nil, id, EventType, "application/json"},
		{make([]byte, 4097), id, EventType, "application/json"},
	} {
		store := &fakeStore{}
		if Handle(context.Background(), store, c.body, c.id, c.typ, c.content) != DeadLetter || store.calls != 0 {
			t.Fatal("invalid envelope reached the store", c.typ, c.content, c.id)
		}
	}
	store := &fakeStore{}
	if Handle(context.Background(), store, body, id, EventType, "application/json") != Ack || store.calls != 1 {
		t.Fatal("valid delivery not applied")
	}
}

func TestClassification(t *testing.T) {
	for code, want := range map[pq.ErrorCode]Disposition{
		"40001": Requeue, "40P01": Requeue, "08006": Requeue, "53300": Requeue,
		"22023": DeadLetter, "23505": DeadLetter, "P0002": DeadLetter, "42501": DeadLetter, "XX000": DeadLetter,
	} {
		if got := Classify(&pq.Error{Code: code}); got != want {
			t.Fatal("wrong disposition", code, got)
		}
	}
	if Classify(errors.New("connection reset")) != Requeue || Classify(context.DeadlineExceeded) != Requeue {
		t.Fatal("uncertain outcome not retried")
	}
	if Classify(nil) != Ack {
		t.Fatal("success not acknowledged")
	}
}
