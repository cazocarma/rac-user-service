package listings

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/cazocarma/rac-platform/contentsignals"
)

type analyzerFunc func(context.Context, string) (contentsignals.Result, error)

func (f analyzerFunc) Analyze(ctx context.Context, text string) (contentsignals.Result, error) {
	return f(ctx, text)
}

func fixturePolicy() Policy {
	// Synthetic bounds and area IDs, not an approval of commercial prices/CUT.
	return Policy{Version: "fixture-1", MinPriceCLP: 1000, MaxPriceCLP: 50000, MaxActivities: 5, AllowedActivities: []string{"cine", "karaoke"}, AllowedAreas: []string{"area_test"}}
}
func fixtureDraft() Draft {
	return Draft{DisplayName: "Cris", Biography: "Me gustan los museos", Description: "Compartamos una tarde de cine y conversación", Activities: []Activity{{Slug: "cine", Note: "Cine de comedia"}}, PriceCLPPerHour: 12000, Interests: []string{"Museos", "Running"}}
}
func preparer(t *testing.T) *Preparer {
	t.Helper()
	engine, err := contentsignals.New(contentsignals.ProposedLexicon())
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPreparer(fixturePolicy(), engine)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSubmissionFreezesCanonicalPayloadAndProof(t *testing.T) {
	p := preparer(t)
	draft := fixtureDraft()
	draft.Activities = append(draft.Activities, Activity{Slug: "karaoke", Note: "Cantar en grupo"})
	first, err := p.Prepare(context.Background(), draft)
	if err != nil {
		t.Fatal(err)
	}
	if first.Hash() != sha256.Sum256(first.Payload()) || first.RiskScore() != 0 {
		t.Fatal("invalid hash/risk")
	}
	secondDraft := draft
	secondDraft.DisplayName = "  Cris "
	secondDraft.Activities = []Activity{draft.Activities[1], draft.Activities[0]}
	secondDraft.Interests = []string{"Running", "Museos"}
	second, err := p.Prepare(context.Background(), secondDraft)
	if err != nil || first.Hash() != second.Hash() {
		t.Fatal("equivalent snapshots must have one hash", err)
	}
	original := string(first.Payload())
	draft.Activities[0].Note = "mutated input"
	draft.Interests[0] = "mutated input"
	data := first.Payload()
	data[0] = 'x'
	proof := first.Assessment()
	proof[0] = 'x'
	if string(first.Payload()) != original || !json.Valid(first.Assessment()) {
		t.Fatal("caller mutated frozen submission")
	}
	if !strings.Contains(string(first.Assessment()), "sexual_services") {
		t.Fatal("unevaluated categories must be retained")
	}
}

func TestSubmissionRejectsContactsOnEveryPublicSurface(t *testing.T) {
	p := preparer(t)
	for name, edit := range map[string]func(*Draft){
		"display_name":         func(d *Draft) { d.DisplayName = "@compa_test" },
		"biography":            func(d *Draft) { d.Biography = "hola arroba ejemplo punto com" },
		"description":          func(d *Draft) { d.Description = "Conversemos por WhatsApp antes de reservar" },
		"interests":            func(d *Draft) { d.Interests = []string{"https://example.com"} },
		"activities.cine.note": func(d *Draft) { d.Activities[0].Note = "+56 9 1234 5678" },
	} {
		t.Run(name, func(t *testing.T) {
			d := fixtureDraft()
			edit(&d)
			submission, err := p.Prepare(context.Background(), d)
			var contact ContactError
			if !errors.Is(err, ErrContact) || !errors.As(err, &contact) || contact.Field != name || len(submission.Payload()) != 0 || err.Error() != ErrContact.Error() {
				t.Fatal("contact must fail without payload or private diagnostic", err)
			}
		})
	}
}

func TestSuspicionRemainsReviewableAndDoesNotBecomeContactOrApproval(t *testing.T) {
	d := fixtureDraft()
	d.Description = "Vendo m.e.r.c.a por gramo con delivery"
	s, err := preparer(t).Prepare(context.Background(), d)
	if err != nil || s.RiskScore() < 70 || !strings.Contains(string(s.Assessment()), "drugs") {
		t.Fatal("suspicion must be retained for review", s.RiskScore(), err)
	}
	// Submission has no approved/published state: a score of zero or a match
	// cannot bypass the separate human decision and commit-time gates.
}

func TestDraftRejectsUnknownCategoriesPricesAndExternalMedia(t *testing.T) {
	p := preparer(t)
	for name, edit := range map[string]func(*Draft){
		"unknown":        func(d *Draft) { d.Activities[0].Slug = "anything" },
		"duplicate":      func(d *Draft) { d.Activities = append(d.Activities, d.Activities[0]) },
		"none":           func(d *Draft) { d.Activities = nil },
		"low price":      func(d *Draft) { d.PriceCLPPerHour = 999 },
		"high price":     func(d *Draft) { d.PriceCLPPerHour = 50001 },
		"external image": func(d *Draft) { d.PhotoVersion = "https://tracker.example/image.jpg" },
		"unknown area":   func(d *Draft) { d.AreaCode = "private_address" },
		"long note":      func(d *Draft) { d.Activities[0].Note = strings.Repeat("á", 141) },
		"invalid UTF8":   func(d *Draft) { d.Biography = "\xff" },
		"control":        func(d *Draft) { d.DisplayName = "Cris\nOtra" },
	} {
		t.Run(name, func(t *testing.T) {
			d := fixtureDraft()
			edit(&d)
			if _, err := p.Prepare(context.Background(), d); !errors.Is(err, ErrInvalidDraft) {
				t.Fatal("invalid draft accepted", err)
			}
		})
	}
	for _, price := range []int64{1000, 50000} {
		d := fixtureDraft()
		d.PriceCLPPerHour = price
		if _, err := p.Prepare(context.Background(), d); err != nil {
			t.Fatal("inclusive bound rejected", err)
		}
	}
}

func TestPolicyIsExplicitAndDetachedFromCaller(t *testing.T) {
	engine, _ := contentsignals.New(contentsignals.ProposedLexicon())
	if _, err := NewPreparer(Policy{}, engine); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("missing policy must not default to permissive")
	}
	if _, err := NewPreparer(fixturePolicy(), nil); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("missing analyzer accepted")
	}
	policy := fixturePolicy()
	p, err := NewPreparer(policy, engine)
	if err != nil {
		t.Fatal(err)
	}
	policy.AllowedActivities[0] = "anything"
	policy.AllowedAreas[0] = "private_address"
	if _, err := p.Prepare(context.Background(), fixtureDraft()); err != nil {
		t.Fatal("caller mutated effective policy", err)
	}
	policy = fixturePolicy()
	policy.RequireArea = true
	p, err = NewPreparer(policy, engine)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Prepare(context.Background(), fixtureDraft()); !errors.Is(err, ErrInvalidDraft) {
		t.Fatal("required public area omitted")
	}
}

func TestAnalysisErrorsAndVersionDriftFailClosed(t *testing.T) {
	for _, mode := range []string{"error", "missing_version", "version_drift", "nan", "span"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			analyzer := analyzerFunc(func(context.Context, string) (contentsignals.Result, error) {
				calls++
				r := contentsignals.Result{AnalyzerVersion: "fixture-1", PolicyVersion: "lexicon-1"}
				switch mode {
				case "error":
					return r, errors.New("private provider failure")
				case "missing_version":
					r.PolicyVersion = ""
				case "version_drift":
					if calls > 1 {
						r.PolicyVersion = "lexicon-2"
					}
				case "nan":
					r.Signals = []contentsignals.Signal{{Category: "drugs", Score: math.NaN()}}
				case "span":
					r.Signals = []contentsignals.Signal{{Category: "drugs", RuleID: "test.rule", Score: 0.5, Spans: []contentsignals.Span{{Start: 0, End: 9999}}}}
				}
				return r, nil
			})
			p, err := NewPreparer(fixturePolicy(), analyzer)
			if err != nil {
				t.Fatal(err)
			}
			s, err := p.Prepare(context.Background(), fixtureDraft())
			if !errors.Is(err, ErrAnalysis) || len(s.Payload()) != 0 || err.Error() != ErrAnalysis.Error() {
				t.Fatal("bad analysis escaped", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := preparer(t).Prepare(ctx, fixtureDraft()); !errors.Is(err, ErrAnalysis) {
		t.Fatal("canceled analysis passed", err)
	}
}

func TestSubmissionStorageBudgetsFailBeforeTransaction(t *testing.T) {
	policy := fixturePolicy()
	policy.MaxActivities = 12
	policy.AllowedActivities = nil
	draft := fixtureDraft()
	draft.Activities = nil
	for i := 0; i < 12; i++ {
		slug := "activity_" + strconv.Itoa(i)
		policy.AllowedActivities = append(policy.AllowedActivities, slug)
		draft.Activities = append(draft.Activities, Activity{Slug: slug, Note: strings.Repeat("🟦", 140)})
	}
	draft.DisplayName = strings.Repeat("🟦", 120)
	draft.Biography = strings.Repeat("🟦", 600)
	draft.Description = strings.Repeat("🟦", 1500)
	draft.Interests = nil
	for i := 0; i < 15; i++ {
		draft.Interests = append(draft.Interests, strings.Repeat("🟦", 38)+strconv.Itoa(i))
	}
	engine, _ := contentsignals.New(contentsignals.ProposedLexicon())
	p, err := NewPreparer(policy, engine)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Prepare(context.Background(), draft); !errors.Is(err, ErrInvalidDraft) {
		t.Fatal("oversized aggregate payload reached storage", err)
	}
	adapter := analyzerFunc(func(context.Context, string) (contentsignals.Result, error) {
		return contentsignals.Result{AnalyzerVersion: "fixture-1", PolicyVersion: "lexicon-1", Unevaluated: []string{strings.Repeat("x", maxAssessmentBytes)}}, nil
	})
	p, err = NewPreparer(fixturePolicy(), adapter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Prepare(context.Background(), fixtureDraft()); !errors.Is(err, ErrAnalysis) {
		t.Fatal("oversized proof reached storage", err)
	}
}
