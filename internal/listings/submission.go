// Package listings owns immutable public snapshots. Preparing a submission is
// not publishing it: every result still requires a human decision and the final
// transactional standing/identity/documents/catalog checks.
package listings

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cazocarma/rac-platform/contentsignals"
)

const PayloadVersion = "rac-listing-payload/1"
const maxPayloadBytes = 16384

// Leave room for PostgreSQL's JSONB whitespace when enforcing its 64 KiB limit.
const maxAssessmentBytes = 32768

var (
	ErrInvalidPolicy  = errors.New("invalid_listing_policy")
	ErrInvalidDraft   = errors.New("invalid_listing_draft")
	ErrAnalysis       = errors.New("listing_analysis_unavailable")
	ErrContact        = errors.New("public_contact_not_allowed")
	identifier        = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	versionIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	photoVersion      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

type Activity struct {
	Slug string `json:"slug"`
	Note string `json:"note"`
}

// Draft has no account phone/email, raw address, role or approval fields.
// AreaCode is a separately selected public area, never copied from private city.
// PhotoVersion references an immutable managed object, never an external URL.
type Draft struct {
	DisplayName     string     `json:"display_name"`
	Biography       string     `json:"biography"`
	Interests       []string   `json:"interests"`
	Description     string     `json:"description"`
	Activities      []Activity `json:"activities"`
	PriceCLPPerHour int64      `json:"price_clp_per_hour"`
	PhotoVersion    string     `json:"photo_version"`
	AreaCode        string     `json:"area_code"`
}

// Policy has no permissive production defaults. Its owner supplies an explicit
// version, price bounds and effective catalog. This type does not approve D04.
type Policy struct {
	Version           string
	MinPriceCLP       int64
	MaxPriceCLP       int64
	MaxActivities     int
	AllowedActivities []string
	AllowedAreas      []string
	RequireArea       bool
}

type Preparer struct {
	policy   Policy
	analyzer contentsignals.Analyzer
}

func NewPreparer(policy Policy, analyzer contentsignals.Analyzer) (*Preparer, error) {
	if analyzer == nil || !versionIdentifier.MatchString(policy.Version) || policy.MinPriceCLP < 0 || policy.MaxPriceCLP <= 0 || policy.MaxPriceCLP < policy.MinPriceCLP || policy.MaxActivities < 1 || policy.MaxActivities > 12 || len(policy.AllowedActivities) == 0 || (policy.RequireArea && len(policy.AllowedAreas) == 0) {
		return nil, ErrInvalidPolicy
	}
	for i, values := range [][]string{policy.AllowedActivities, policy.AllowedAreas} {
		seen := map[string]bool{}
		for _, value := range values {
			valid := identifier.MatchString(value)
			if i == 1 {
				valid = versionIdentifier.MatchString(value)
			}
			if !valid || seen[value] {
				return nil, ErrInvalidPolicy
			}
			seen[value] = true
		}
	}
	policy.AllowedActivities = slices.Clone(policy.AllowedActivities)
	policy.AllowedAreas = slices.Clone(policy.AllowedAreas)
	return &Preparer{policy: policy, analyzer: analyzer}, nil
}

// Submission exposes copies so neither the caller nor an analyzer retaining
// references can change the payload/assessment after its hash is computed.
type Submission struct {
	payload       []byte
	assessment    []byte
	hash          [32]byte
	risk          int
	policyVersion string
}

func (s Submission) Payload() json.RawMessage    { return slices.Clone(s.payload) }
func (s Submission) Assessment() json.RawMessage { return slices.Clone(s.assessment) }
func (s Submission) Hash() [32]byte              { return s.hash }
func (s Submission) RiskScore() int              { return s.risk }

type ContactError struct{ Field string }

func (e ContactError) Error() string { return ErrContact.Error() }
func (e ContactError) Unwrap() error { return ErrContact }

type fieldAssessment struct {
	Field  string                `json:"field"`
	Result contentsignals.Result `json:"result"`
}

func clean(text string, max int, multiline bool) (string, bool) {
	text = strings.TrimSpace(text)
	return text, utf8.ValidString(text) && utf8.RuneCountInString(text) <= max && !strings.ContainsFunc(text, func(r rune) bool {
		return unicode.IsControl(r) && !(multiline && r == '\n')
	})
}

func (p *Preparer) normalize(d Draft) (Draft, error) {
	var ok bool
	if d.DisplayName, ok = clean(d.DisplayName, 120, false); !ok || utf8.RuneCountInString(d.DisplayName) < 2 {
		return Draft{}, ErrInvalidDraft
	}
	if d.Biography, ok = clean(d.Biography, 600, true); !ok {
		return Draft{}, ErrInvalidDraft
	}
	if d.Description, ok = clean(d.Description, 1500, true); !ok || utf8.RuneCountInString(d.Description) < 20 {
		return Draft{}, ErrInvalidDraft
	}
	if d.PriceCLPPerHour < p.policy.MinPriceCLP || d.PriceCLPPerHour > p.policy.MaxPriceCLP || len(d.Activities) < 1 || len(d.Activities) > p.policy.MaxActivities || len(d.Interests) > 15 || (d.PhotoVersion != "" && !photoVersion.MatchString(d.PhotoVersion)) || (p.policy.RequireArea && d.AreaCode == "") || (d.AreaCode != "" && !slices.Contains(p.policy.AllowedAreas, d.AreaCode)) {
		return Draft{}, ErrInvalidDraft
	}
	d.Activities = slices.Clone(d.Activities)
	seen := map[string]bool{}
	for i, a := range d.Activities {
		if a.Note, ok = clean(a.Note, 140, false); !ok || !slices.Contains(p.policy.AllowedActivities, a.Slug) || seen[a.Slug] {
			return Draft{}, ErrInvalidDraft
		}
		seen[a.Slug] = true
		d.Activities[i] = a
	}
	slices.SortFunc(d.Activities, func(a, b Activity) int { return strings.Compare(a.Slug, b.Slug) })
	d.Interests = slices.Clone(d.Interests)
	if d.Interests == nil {
		d.Interests = []string{}
	}
	seen = map[string]bool{}
	for i, interest := range d.Interests {
		interest, ok = clean(interest, 40, false)
		key := strings.ToLower(interest)
		if !ok || interest == "" || seen[key] {
			return Draft{}, ErrInvalidDraft
		}
		seen[key] = true
		d.Interests[i] = interest
	}
	slices.Sort(d.Interests)
	return d, nil
}

func (p *Preparer) Prepare(ctx context.Context, draft Draft) (Submission, error) {
	draft, err := p.normalize(draft)
	if err != nil {
		return Submission{}, err
	}
	fields := []struct{ field, text string }{{"display_name", draft.DisplayName}, {"biography", draft.Biography}, {"description", draft.Description}, {"interests", strings.Join(draft.Interests, " ")}}
	for _, a := range draft.Activities {
		fields = append(fields, struct{ field, text string }{"activities." + a.Slug + ".note", a.Note})
	}
	assessment := struct {
		ListingPolicyVersion string            `json:"listing_policy_version"`
		Fields               []fieldAssessment `json:"fields"`
	}{ListingPolicyVersion: p.policy.Version}
	var analyzerVersion, lexiconVersion string
	risk := 0
	analysisBytes := 0
	for _, field := range fields {
		result, err := p.analyzer.Analyze(ctx, field.text)
		if err != nil || result.AnalyzerVersion == "" || result.PolicyVersion == "" || (analyzerVersion != "" && (result.AnalyzerVersion != analyzerVersion || result.PolicyVersion != lexiconVersion)) {
			return Submission{}, ErrAnalysis
		}
		analyzerVersion, lexiconVersion = result.AnalyzerVersion, result.PolicyVersion
		for _, signal := range result.Signals {
			if signal.Category == contentsignals.CategoryContact {
				return Submission{}, ContactError{Field: field.field}
			}
			if math.IsNaN(signal.Score) || math.IsInf(signal.Score, 0) || signal.Score <= 0 || signal.Score > 1 {
				return Submission{}, ErrAnalysis
			}
			if signal.RuleID == "" || len(signal.Spans) == 0 {
				return Submission{}, ErrAnalysis
			}
			for _, span := range signal.Spans {
				if span.Start < 0 || span.End <= span.Start || span.End > len(field.text) || !utf8.ValidString(field.text[span.Start:span.End]) {
					return Submission{}, ErrAnalysis
				}
			}
		}
		for _, score := range result.Scores() {
			risk = max(risk, int(math.Ceil(score*100)))
		}
		// Serialize before invoking the analyzer again: an adapter may reuse its
		// backing arrays. Do not let a subsequent evaluation rewrite earlier proof.
		encoded, err := json.Marshal(result)
		analysisBytes += len(encoded)
		if err != nil || analysisBytes > maxAssessmentBytes {
			return Submission{}, ErrAnalysis
		}
		var frozen contentsignals.Result
		if json.Unmarshal(encoded, &frozen) != nil {
			return Submission{}, ErrAnalysis
		}
		assessment.Fields = append(assessment.Fields, fieldAssessment{Field: field.field, Result: frozen})
	}
	if ctx.Err() != nil {
		return Submission{}, ErrAnalysis
	}
	payload, err := json.Marshal(draft)
	if err != nil || len(payload) > maxPayloadBytes {
		return Submission{}, ErrInvalidDraft
	}
	proof, err := json.Marshal(assessment)
	if err != nil || len(proof) > maxAssessmentBytes {
		return Submission{}, ErrAnalysis
	}
	return Submission{payload: payload, assessment: proof, hash: sha256.Sum256(payload), risk: risk, policyVersion: p.policy.Version}, nil
}
