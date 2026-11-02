package contentsignals

import (
	"errors"
	"math"
	"regexp"
	"slices"
	"strings"
)

const (
	CategoryContact            = "contact"
	CategoryDrugs              = "drugs"
	CategorySexualServices     = "sexual_services"
	CategoryWeapons            = "weapons"
	CategoryViolence           = "violence"
	CategoryMinors             = "minors"
	CategoryOffplatformPayment = "offplatform_payment"
)

var supportedLexiconCategories = [...]string{CategoryDrugs, CategorySexualServices, CategoryWeapons, CategoryViolence, CategoryMinors, CategoryOffplatformPayment}

// Categories returns an independent copy. A category without curated rules is
// unevaluated, never passed. Callers cannot rewrite the engine's policy domain.
func Categories() []string { return slices.Clone(supportedLexiconCategories[:]) }

// LexiconCategories is a compatibility copy; changes do not affect analysis.
// Deprecated: use Categories to obtain an independent copy.
var LexiconCategories = Categories()

var (
	ErrInvalidLexicon = errors.New("invalid content lexicon")
	ruleIDPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z0-9_.]{1,63}$`)
	versionPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// Rule matches whole-word term sequences. RequiresAny demands one context
// term elsewhere in the text; ExcludeIfAny suppresses the rule when a benign
// context term is present ("hongos" next to cooking words).
type Rule struct {
	ID           string   `json:"id"`
	Category     string   `json:"category"`
	Terms        []string `json:"terms"`
	Weight       float64  `json:"weight"`
	RequiresAny  []string `json:"requires_any,omitempty"`
	ExcludeIfAny []string `json:"exclude_if_any,omitempty"`
}

// Lexicon is an immutable, versioned rule set. Status records whether T&S
// approved it; a proposed lexicon is usable for DEV and corpus runs only.
type Lexicon struct {
	Version string `json:"version"`
	Status  string `json:"status"`
	Rules   []Rule `json:"rules"`
}

func (l Lexicon) Validate() error {
	if !versionPattern.MatchString(l.Version) || (l.Status != "proposed" && l.Status != "approved") {
		return ErrInvalidLexicon
	}
	known := map[string]bool{}
	for _, c := range supportedLexiconCategories {
		known[c] = true
	}
	seen := map[string]bool{}
	for _, r := range l.Rules {
		if !ruleIDPattern.MatchString(r.ID) || seen[r.ID] || !known[r.Category] || math.IsNaN(r.Weight) || math.IsInf(r.Weight, 0) || r.Weight <= 0 || r.Weight > 1 || len(r.Terms) == 0 {
			return ErrInvalidLexicon
		}
		seen[r.ID] = true
		for _, group := range [][]string{r.Terms, r.RequiresAny, r.ExcludeIfAny} {
			for _, term := range group {
				if normalizeTerm(term) == "" || len(term) > 64 {
					return ErrInvalidLexicon
				}
			}
		}
	}
	return nil
}

type compiledRule struct {
	rule            Rule
	terms, requires [][]string
	excludes        [][]string
}

func words(term string) []string { return strings.Fields(normalizeTerm(term)) }

func compile(l Lexicon) []compiledRule {
	out := make([]compiledRule, 0, len(l.Rules))
	for _, r := range l.Rules {
		c := compiledRule{rule: r}
		for _, t := range r.Terms {
			c.terms = append(c.terms, words(t))
		}
		for _, t := range r.RequiresAny {
			c.requires = append(c.requires, words(t))
		}
		for _, t := range r.ExcludeIfAny {
			c.excludes = append(c.excludes, words(t))
		}
		out = append(out, c)
	}
	return out
}

// find returns the word index of every occurrence of phrase in text.
func find(text []string, phrase []string) []int {
	hits := []int{}
	for i := 0; i+len(phrase) <= len(text); i++ {
		match := true
		for j := range phrase {
			if text[i+j] != phrase[j] {
				match = false
				break
			}
		}
		if match {
			hits = append(hits, i)
		}
	}
	return hits
}

func anyPresent(text []string, phrases [][]string) bool {
	for _, p := range phrases {
		if len(find(text, p)) > 0 {
			return true
		}
	}
	return false
}

func detectLexicon(input string, rules []compiledRule) []Signal {
	v := lexiconView(input)
	ranges := splitWords(v)
	text := make([]string, len(ranges))
	for i, r := range ranges {
		text[i] = string(v.text[r[0]:r[1]])
	}
	signals := []Signal{}
	for _, c := range rules {
		if len(c.requires) > 0 && !anyPresent(text, c.requires) {
			continue
		}
		if anyPresent(text, c.excludes) {
			continue
		}
		var spans []Span
		for _, phrase := range c.terms {
			for _, i := range find(text, phrase) {
				spans = append(spans, v.span(ranges[i][0], ranges[i+len(phrase)-1][1]))
			}
		}
		if len(spans) > 0 {
			signals = append(signals, Signal{Category: c.rule.Category, RuleID: c.rule.ID, Score: c.rule.Weight, Spans: spans})
		}
	}
	return signals
}
