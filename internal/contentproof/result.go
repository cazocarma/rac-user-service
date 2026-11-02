// Package contentproof freezes validated private analyzer output for user-owned
// listings and photos. It applies no publication or account-sanction policy.
package contentproof

import (
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cazocarma/rac-platform/contentsignals"
)

var ErrInvalid = errors.New("invalid_content_analysis")

func label(value string) bool {
	return len(value) > 0 && len(value) <= 128 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

func Freeze(input string, result contentsignals.Result, limit int) (contentsignals.Result, error) {
	if !utf8.ValidString(input) || limit < 1 || !label(result.AnalyzerVersion) || !label(result.PolicyVersion) || len(result.Signals) > 1024 {
		return contentsignals.Result{}, ErrInvalid
	}
	categories := contentsignals.Categories()
	categories = append(categories, contentsignals.CategoryContact)
	total := 0
	for _, signal := range result.Signals {
		if !slices.Contains(categories, signal.Category) || !label(signal.RuleID) || math.IsNaN(signal.Score) || math.IsInf(signal.Score, 0) || signal.Score <= 0 || signal.Score > 1 || len(signal.Spans) == 0 {
			return contentsignals.Result{}, ErrInvalid
		}
		total += len(signal.Spans)
		if total > 4096 {
			return contentsignals.Result{}, ErrInvalid
		}
		for _, span := range signal.Spans {
			if span.Start < 0 || span.End <= span.Start || span.End > len(input) || !utf8.ValidString(input[span.Start:span.End]) {
				return contentsignals.Result{}, ErrInvalid
			}
		}
	}
	seen := map[string]bool{}
	for _, category := range result.Unevaluated {
		if !slices.Contains(contentsignals.Categories(), category) || seen[category] {
			return contentsignals.Result{}, ErrInvalid
		}
		seen[category] = true
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > limit {
		return contentsignals.Result{}, ErrInvalid
	}
	var frozen contentsignals.Result
	if json.Unmarshal(encoded, &frozen) != nil {
		return contentsignals.Result{}, ErrInvalid
	}
	return frozen, nil
}
