package contentsignals

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
)

// AnalyzerVersion changes whenever normalization or detectors change, so a
// stored result can be traced to the code that produced it.
const AnalyzerVersion = "contentsignals/1"

var ErrTooLarge = errors.New("content exceeds analysis limit")

// Contextual patterns add signal toward a category; they are never a verdict.
var patterns = []struct {
	rule, category string
	weight         float64
	expression     *regexp.Regexp
}{
	{"pattern.price_per_weight", CategoryDrugs, 0.5, regexp.MustCompile(`(\$\s?\d[\d.]*|\d+\s?(lucas?|mil))\s*(x|por|el|la|c/u)\s*(g|gr|grs|gramos?|kg|kilos?)\b|\b\d+\s?(g|gr|grs|gramos?)\s*(a|en|x|por)\s*\$?\s?\d`)},
	{"pattern.stock_list", CategoryDrugs, 0.3, regexp.MustCompile(`\b(stock|disponible|disponibles)\b[^\n]{0,60}\b(g|gr|grs|gramos?|pastillas?|unidades)\b`)},
	{"pattern.delivery", CategoryDrugs, 0.3, regexp.MustCompile(`\b(delivery|envios?|despachos?)\b[^\n]{0,40}(24/7|todo el dia|a domicilio|discreto|discretos)`)},
}

// Emoji commonly combined in drug offers; one alone is ordinary.
var drugEmoji = []string{"🍃", "🌿", "❄", "💊", "🍄", "🔌"}

func detectPatterns(input string) []Signal {
	v := contactView(input)
	text := string(v.text)
	runeAt := make([]int, len(text)+1)
	count := 0
	for i := range text {
		runeAt[i] = count
		count++
	}
	runeAt[len(text)] = count
	signals := []Signal{}
	for _, p := range patterns {
		var spans []Span
		for _, m := range p.expression.FindAllStringIndex(text, -1) {
			if a, b := runeAt[m[0]], runeAt[m[1]]; b > a {
				spans = append(spans, v.span(a, b))
			}
		}
		if len(spans) > 0 {
			signals = append(signals, Signal{Category: p.category, RuleID: p.rule, Score: p.weight, Spans: spans})
		}
	}
	var emojiSpans []Span
	for _, e := range drugEmoji {
		if i := strings.Index(input, e); i >= 0 {
			emojiSpans = append(emojiSpans, Span{Start: i, End: i + len(e)})
		}
	}
	if len(emojiSpans) >= 2 {
		signals = append(signals, Signal{Category: CategoryDrugs, RuleID: "pattern.emoji_combo", Score: 0.4, Spans: emojiSpans})
	}
	return signals
}

// Engine is the single shared analyzer for every surface.
type Engine struct {
	lexicon Lexicon
	rules   []compiledRule
}

func New(lexicon Lexicon) (*Engine, error) {
	if err := lexicon.Validate(); err != nil {
		return nil, err
	}
	// Hot reload builds another engine. Callers must not be able to change the
	// current snapshot or its unevaluated categories by reusing input buffers.
	rules := slices.Clone(lexicon.Rules)
	for i := range rules {
		rules[i].Terms = slices.Clone(rules[i].Terms)
		rules[i].RequiresAny = slices.Clone(rules[i].RequiresAny)
		rules[i].ExcludeIfAny = slices.Clone(rules[i].ExcludeIfAny)
	}
	lexicon.Rules = rules
	return &Engine{lexicon: lexicon, rules: compile(lexicon)}, nil
}

func (e *Engine) Analyze(ctx context.Context, input string) (Result, error) {
	if len(input) > MaxInput {
		return Result{}, ErrTooLarge
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	signals := detectContact(input)
	signals = append(signals, detectLexicon(input, e.rules)...)
	signals = append(signals, detectPatterns(input)...)
	covered := map[string]bool{}
	for _, r := range e.lexicon.Rules {
		covered[r.Category] = true
	}
	unevaluated := []string{}
	for _, c := range supportedLexiconCategories {
		if !covered[c] {
			unevaluated = append(unevaluated, c)
		}
	}
	return Result{AnalyzerVersion: AnalyzerVersion, PolicyVersion: e.lexicon.Version, Signals: signals, Unevaluated: unevaluated}, ctx.Err()
}

// Scores sums rule weights per category, capped at 1.
func (r Result) Scores() map[string]float64 {
	scores := map[string]float64{}
	for _, s := range r.Signals {
		scores[s.Category] = min(1, scores[s.Category]+s.Score)
	}
	return scores
}

var _ Analyzer = (*Engine)(nil)
