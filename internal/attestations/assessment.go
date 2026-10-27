// Package attestations evaluates the reviewed compa declarations and three
// scenario questions. Passing is a prerequisite, never identity verification,
// document consent, publication approval, standing permission, or a role grant.
package attestations

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cazocarma/rac-platform/standing"
)

var (
	ErrUnavailable  = errors.New("attestation definition unavailable")
	ErrChanged      = errors.New("attestation version changed")
	ErrDeclarations = errors.New("all declarations must be explicitly affirmed")
	ErrQuiz         = errors.New("all scenario questions must be answered correctly")
)
var identifier = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var version = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var statementIDs = map[string]bool{
	"no_illicit_substances": true, "no_sexual_services": true,
	"catalog_only": true, "adults_only": true, "enforcement_and_appeal": true,
}

type Statement struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}
type Option struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}
type Question struct {
	ID            string   `json:"id"`
	Text          string   `json:"text"`
	Options       []Option `json:"options"`
	CorrectOption string   `json:"correct_option"`
}

// Content is canonicalized with encoding/json, preserving the reviewed array
// order. A revision of text, options, order or answer key changes its SHA256.
type Content struct {
	Statements []Statement `json:"statements"`
	Questions  []Question  `json:"questions"`
}

func (c Content) Digest() [32]byte {
	raw, _ := json.Marshal(c)
	return sha256.Sum256(raw)
}

type Definition struct {
	Version         string
	Locale          string
	RegistryVersion uint64
	PolicyVersion   string
	Content         Content
	SHA256          [32]byte
	Approved        bool
	ApprovedBy      string
	ReviewedAt      time.Time
	PublishedAt     time.Time
}
type Submission struct {
	Version string   `json:"version"`
	SHA256  [32]byte `json:"-"`
	// False, absent or additional declarations are not implied consent.
	Statements map[string]bool   `json:"statements"`
	Answers    map[string]string `json:"answers"`
}
type Passed struct {
	Version         string
	SHA256          [32]byte
	RegistryVersion uint64
	PolicyVersion   string
	PassedAt        time.Time
}

func text(value string, max int) bool {
	if !utf8.ValidString(value) || strings.TrimSpace(value) == "" || utf8.RuneCountInString(value) > max {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}
func (d Definition) Validate(now time.Time) error {
	if now.IsZero() || !version.MatchString(d.Version) || (d.Locale != "es" && d.Locale != "en") ||
		d.RegistryVersion == 0 || !standing.ValidAccountID(d.PolicyVersion) ||
		!d.Approved || !standing.ValidAccountID(d.ApprovedBy) || d.ReviewedAt.IsZero() ||
		d.PublishedAt.Before(d.ReviewedAt) || d.PublishedAt.After(now) ||
		len(d.Content.Statements) != 5 || len(d.Content.Questions) != 3 {
		return ErrUnavailable
	}
	statements := map[string]bool{}
	for _, s := range d.Content.Statements {
		if !statementIDs[s.ID] || statements[s.ID] || !text(s.Text, 2000) {
			return ErrUnavailable
		}
		statements[s.ID] = true
	}
	questions := map[string]bool{}
	for _, q := range d.Content.Questions {
		if !identifier.MatchString(q.ID) || questions[q.ID] || !text(q.Text, 2000) || len(q.Options) < 2 || len(q.Options) > 4 {
			return ErrUnavailable
		}
		questions[q.ID] = true
		options := map[string]bool{}
		for _, option := range q.Options {
			if !identifier.MatchString(option.ID) || options[option.ID] || !text(option.Text, 1000) {
				return ErrUnavailable
			}
			options[option.ID] = true
		}
		if !options[q.CorrectOption] {
			return ErrUnavailable
		}
	}
	if d.SHA256 != d.Content.Digest() {
		return ErrUnavailable
	}
	return nil
}

// Evaluate is pure: the owner must read a current definition and fence it in
// the same transaction that records the authenticated subject's first pass.
// Failed attempts are not stored here; they never cause an automatic sanction.
func Evaluate(d Definition, input Submission, now time.Time) (Passed, error) {
	if err := d.Validate(now); err != nil {
		return Passed{}, err
	}
	if input.Version != d.Version || input.SHA256 != d.SHA256 {
		return Passed{}, ErrChanged
	}
	if len(input.Statements) != len(d.Content.Statements) {
		return Passed{}, ErrDeclarations
	}
	for _, s := range d.Content.Statements {
		if !input.Statements[s.ID] {
			return Passed{}, ErrDeclarations
		}
	}
	if len(input.Answers) != len(d.Content.Questions) {
		return Passed{}, ErrQuiz
	}
	for _, q := range d.Content.Questions {
		if input.Answers[q.ID] != q.CorrectOption {
			return Passed{}, ErrQuiz
		}
	}
	return Passed{Version: d.Version, SHA256: d.SHA256, RegistryVersion: d.RegistryVersion, PolicyVersion: d.PolicyVersion, PassedAt: now}, nil
}

// PublicQuestion structurally excludes the answer key; callers cannot expose
// it accidentally by serializing a Question from the authoritative definition.
type PublicQuestion struct {
	ID      string   `json:"id"`
	Text    string   `json:"text"`
	Options []Option `json:"options"`
}
type PublicContent struct {
	Statements []Statement      `json:"statements"`
	Questions  []PublicQuestion `json:"questions"`
}

func (d Definition) Public(now time.Time) (PublicContent, error) {
	if err := d.Validate(now); err != nil {
		return PublicContent{}, err
	}
	result := PublicContent{Statements: append([]Statement(nil), d.Content.Statements...)}
	for _, q := range d.Content.Questions {
		result.Questions = append(result.Questions, PublicQuestion{ID: q.ID, Text: q.Text, Options: append([]Option(nil), q.Options...)})
	}
	return result, nil
}
