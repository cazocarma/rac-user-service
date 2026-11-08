package tseffects

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeExpiries struct {
	due       []string
	failOn    string
	refreshed []string
	dueErr    error
}

func (f *fakeExpiries) Due(context.Context, int) ([]string, error) { return f.due, f.dueErr }

func (f *fakeExpiries) Refresh(_ context.Context, subject string) (bool, error) {
	if subject == f.failOn {
		return false, errors.New("serialization failure")
	}
	f.refreshed = append(f.refreshed, subject)
	return subject != "bbbbbbbb-1111-4111-8111-111111111111", nil
}

func TestSweepRefreshesOnlyValidDueSubjects(t *testing.T) {
	store := &fakeExpiries{due: []string{"aaaaaaaa-1111-4111-8111-111111111111", "not-a-subject",
		"bbbbbbbb-1111-4111-8111-111111111111"}}
	changed, err := SweepExpiries(context.Background(), store)
	if err != nil || changed != 1 || len(store.refreshed) != 2 {
		t.Fatal("unexpected sweep", changed, err, store.refreshed)
	}
}

func TestSweepStopsOnFailureAndReportsDueErrors(t *testing.T) {
	store := &fakeExpiries{due: []string{"aaaaaaaa-1111-4111-8111-111111111111", "cccccccc-1111-4111-8111-111111111111",
		"dddddddd-1111-4111-8111-111111111111"}, failOn: "cccccccc-1111-4111-8111-111111111111"}
	if changed, err := SweepExpiries(context.Background(), store); err == nil || changed != 1 || len(store.refreshed) != 1 {
		t.Fatal("failure did not stop the pass", changed, err)
	}
	if _, err := SweepExpiries(context.Background(), &fakeExpiries{dueErr: errors.New("down")}); err == nil {
		t.Fatal("due error swallowed")
	}
}

func TestLoopReportsCountsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	passes := 0
	RefreshLoop(ctx, &fakeExpiries{due: []string{"aaaaaaaa-1111-4111-8111-111111111111"}}, time.Millisecond, func(changed int, err error) {
		passes++
		if changed != 1 || err != nil {
			t.Error("unexpected report", changed, err)
		}
		if passes == 3 {
			cancel()
		}
	})
	if passes != 3 {
		t.Fatal("loop did not stop after cancellation", passes)
	}
}

func TestConsumerAuthorityIncludesExpiries(t *testing.T) {
	if len(Functions()) != 3 || Functions()[2] != "standing.ts_expiries_due(integer)" {
		t.Fatal("unexpected consumer authority", Functions())
	}
}
