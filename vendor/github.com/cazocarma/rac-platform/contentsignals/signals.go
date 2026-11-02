// Package contentsignals is the single shared analyzer (M5, ADR-006). Rule
// ids and spans are for authorized T&S review only, never public errors.
package contentsignals

import "context"

type Span struct{ Start, End int }
type Signal struct {
	Category, RuleID string
	Score            float64
	Spans            []Span
}
type Result struct {
	AnalyzerVersion, PolicyVersion string
	Signals                        []Signal
	// Unevaluated lists categories without curated rules: never a pass.
	Unevaluated []string
}

// Span coordinates are UTF-8 byte offsets in the original input.
type Analyzer interface {
	Analyze(context.Context, string) (Result, error)
}
