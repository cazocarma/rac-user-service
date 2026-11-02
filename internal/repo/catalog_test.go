package repo

import (
	"strings"
	"testing"
)

func TestNormalizeActivitiesEnforcesTheClosedCatalogShape(t *testing.T) {
	policy := CatalogPolicy{MaxPerCompa: 3}
	got, err := NormalizeActivities([]ActivityInput{{Slug: "cine", Note: "  Estrenos del jueves  "}, {Slug: "running"}}, policy)
	if err != nil || len(got) != 2 || got[0].Note != "Estrenos del jueves" {
		t.Fatal(got, err)
	}
	for name, input := range map[string][]ActivityInput{
		"empty":             {},
		"over maximum":      {{Slug: "cine"}, {Slug: "teatro"}, {Slug: "museos"}, {Slug: "running"}},
		"duplicate":         {{Slug: "cine"}, {Slug: "cine"}},
		"free text":         {{Slug: "masajes relajantes"}},
		"uppercase":         {{Slug: "Cine"}},
		"long note":         {{Slug: "cine", Note: strings.Repeat("a", 141)}},
		"control character": {{Slug: "cine", Note: "llámame\u0000"}},
		"newline":           {{Slug: "cine", Note: "uno\ndos"}},
	} {
		if _, err := NormalizeActivities(input, policy); err != ErrInvalidActivities {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if _, err := NormalizeActivities([]ActivityInput{{Slug: "cine", Note: strings.Repeat("ñ", 140)}}, policy); err != nil {
		t.Fatal("140 characters must be allowed", err)
	}
}

func TestCatalogPolicyServesProposalsOnlyInDevelopment(t *testing.T) {
	for environment, allowed := range map[string]bool{"dev": true, "test": true, "qa": false, "prd": false, "": false} {
		t.Setenv("RAC_ENV", environment)
		t.Setenv("CATALOG_MAX_PER_COMPA", "")
		policy := CatalogFromEnvironment()
		if policy.AllowProposed != allowed || policy.MaxPerCompa != 5 {
			t.Fatal(environment, policy)
		}
	}
	for raw, want := range map[string]int{"3": 3, "12": 12, "0": 5, "13": 5, "x": 5} {
		t.Setenv("CATALOG_MAX_PER_COMPA", raw)
		if got := CatalogFromEnvironment().MaxPerCompa; got != want {
			t.Fatal(raw, got)
		}
	}
	if !strings.Contains(visible(4), "$4") || !strings.Contains(offeredClause(2), "$2") {
		t.Fatal("visibility predicate argument")
	}
}
