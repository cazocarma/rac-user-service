// Package identity owns identity verification results. External providers
// enter only through Provider; this package never sees document images,
// document numbers or birth dates, and email verification grants nothing here.
package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/http"
	"regexp"
)

type Purpose string

const (
	CompaOnboarding Purpose = "compa_onboarding"
	ClientBooking   Purpose = "client_booking"
)

func (p Purpose) Valid() bool { return p == CompaOnboarding || p == ClientBooking }

type Status string

const (
	None        Status = "none"
	Pending     Status = "pending"
	Approved    Status = "approved"
	Rejected    Status = "rejected"
	Expired     Status = "expired"
	NeedsReview Status = "needs_review"
)

// Session is where the person continues with the provider.
type Session struct {
	ProviderRef string
	URL         string
}

// Result is a provider decision taken from a verified webhook. IdentityKey is
// the provider's stable opaque identifier for the identity, never a document
// number; it only feeds the fingerprint and is not persisted.
type Result struct {
	EventID         string
	ProviderRef     string
	Outcome         Status
	Adult           *bool
	DocumentCountry string
	IdentityKey     []byte
}

// Provider is the port of ADR-005. VerifyWebhook authenticates the original
// request bytes and rejects replays outside its time window; event ids are
// additionally deduplicated by the store.
type Provider interface {
	Name() string
	CreateSession(ctx context.Context, providerSubject string, purpose Purpose) (Session, error)
	VerifyWebhook(r *http.Request) (Result, error)
	DeleteSubjectData(ctx context.Context, providerRef string) error
}

var (
	ErrInvalidWebhook = errors.New("identity_webhook_invalid")
	ErrInvalidResult  = errors.New("identity_result_invalid")
	ErrUnavailable    = errors.New("identity_unavailable")
	ErrUnknownSession = errors.New("identity_session_unknown")
	ErrConflict       = errors.New("identity_transition_conflict")
	ErrNoProfile      = errors.New("identity_profile_required")
)

var (
	referencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$`)
	countryPattern   = regexp.MustCompile(`^[A-Z]{2}$`)
	keyIDPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	providerPattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
)

// Validate rejects results the store could not record faithfully.
func (r Result) Validate() error {
	if !referencePattern.MatchString(r.EventID) || !referencePattern.MatchString(r.ProviderRef) {
		return ErrInvalidResult
	}
	switch r.Outcome {
	case Approved:
		if !countryPattern.MatchString(r.DocumentCountry) || len(r.IdentityKey) < 16 || len(r.IdentityKey) > 256 {
			return ErrInvalidResult
		}
	case Rejected, Expired, NeedsReview:
		if r.DocumentCountry != "" && !countryPattern.MatchString(r.DocumentCountry) {
			return ErrInvalidResult
		}
	default:
		return ErrInvalidResult
	}
	return nil
}

// Decide applies RAC rules to a provider outcome. A minor is rejected; an
// undetermined age, a banned fingerprint or one already approved for another
// account goes to human review (D12): never an automatic ban of a new person.
func Decide(r Result, banned, duplicate bool) Status {
	switch r.Outcome {
	case Rejected, Expired:
		return r.Outcome
	case Approved:
	default:
		return NeedsReview
	}
	if r.Adult == nil {
		return NeedsReview
	}
	if !*r.Adult {
		return Rejected
	}
	if banned || duplicate {
		return NeedsReview
	}
	return Approved
}

const fingerprintDomain = "rac/identity-fingerprint/v1"

// Fingerprinter derives a keyed, domain-separated fingerprint. Rotation needs
// a D12 strategy: without stored documents an old fingerprint cannot be
// recomputed, so key_id is recorded with every value.
type Fingerprinter struct {
	keyID string
	key   []byte
}

func NewFingerprinter(keyID string, key []byte) (Fingerprinter, error) {
	if !keyIDPattern.MatchString(keyID) || len(key) < 32 {
		return Fingerprinter{}, errors.New("identity fingerprint key requires an id and at least 32 bytes")
	}
	return Fingerprinter{keyID: keyID, key: append([]byte(nil), key...)}, nil
}

func (f Fingerprinter) KeyID() string { return f.keyID }

func (f Fingerprinter) Fingerprint(country string, identityKey []byte) []byte {
	mac := hmac.New(sha256.New, f.key)
	mac.Write([]byte(fingerprintDomain))
	mac.Write([]byte{0})
	mac.Write([]byte(country))
	mac.Write([]byte{0})
	mac.Write(identityKey)
	return mac.Sum(nil)
}
