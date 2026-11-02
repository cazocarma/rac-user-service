package contentproof

import (
	"errors"
	"math"
	"testing"

	"github.com/cazocarma/rac-platform/contentsignals"
)

func validResult() contentsignals.Result {
	return contentsignals.Result{AnalyzerVersion: "fixture/1", PolicyVersion: "fixture-1", Signals: []contentsignals.Signal{{Category: "drugs", RuleID: "fixture.rule", Score: 0.5, Spans: []contentsignals.Span{{Start: 0, End: 2}}}}, Unevaluated: []string{"minors"}}
}
func TestFreezeBoundsAndSnapshotsAnalysis(t *testing.T) {
	original := validResult()
	frozen, err := Freeze("á", original, 4096)
	if err != nil {
		t.Fatal(err)
	}
	original.Signals[0].Score = 1
	original.Signals[0].Spans[0].End = 999
	original.Unevaluated[0] = "contact"
	if frozen.Signals[0].Score != 0.5 || frozen.Signals[0].Spans[0].End != 2 || frozen.Unevaluated[0] != "minors" {
		t.Fatal("provider rewrote an earlier analysis")
	}
	for name, change := range map[string]func(*contentsignals.Result){
		"invalid UTF8 span":            func(r *contentsignals.Result) { r.Signals[0].Spans[0].Start = 1 },
		"outside span":                 func(r *contentsignals.Result) { r.Signals[0].Spans[0].End = 3 },
		"NaN":                          func(r *contentsignals.Result) { r.Signals[0].Score = math.NaN() },
		"unknown category":             func(r *contentsignals.Result) { r.Signals[0].Category = "invented" },
		"zero score":                   func(r *contentsignals.Result) { r.Signals[0].Score = 0 },
		"missing rule":                 func(r *contentsignals.Result) { r.Signals[0].RuleID = "" },
		"repaired UTF8 label":          func(r *contentsignals.Result) { r.PolicyVersion = string([]byte{255}) },
		"control label":                func(r *contentsignals.Result) { r.AnalyzerVersion = "private\nlabel" },
		"unknown unchecked category":   func(r *contentsignals.Result) { r.Unevaluated = []string{"invented"} },
		"duplicate unchecked category": func(r *contentsignals.Result) { r.Unevaluated = []string{"minors", "minors"} },
	} {
		result := validResult()
		change(&result)
		if _, err := Freeze("á", result, 4096); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid analysis accepted", name, err)
		}
	}
	if _, err := Freeze("á", validResult(), 1); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized proof silently retained")
	}
}
