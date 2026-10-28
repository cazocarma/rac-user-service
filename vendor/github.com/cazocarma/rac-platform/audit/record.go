// Package audit defines the privacy-minimal RAC audit wire format.
// UUIDs are pseudonymous references, not anonymous data. Never use this package
// to store messages, document numbers, emails or free-form justifications.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

const Version = 1
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"
const TimeLayout = "2006-01-02T15:04:05.000000Z"

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidID(s string) bool {
	return uuidPattern.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}

// Record is emitted by the trusted append boundary, never accepted as an
// authenticated actor assertion from a browser. Timestamp and sequence belong
// to the persistence authority. All references must be opaque non-zero UUIDs.
type Record struct {
	Version       int    `json:"version"`
	ChainID       string `json:"chain_id"`
	Sequence      uint64 `json:"sequence"`
	EventID       string `json:"event_id"`
	OccurredAt    string `json:"occurred_at"`
	ActorID       string `json:"actor_id"`
	Action        string `json:"action"`
	ResourceID    string `json:"resource_id"`
	Purpose       string `json:"purpose"`
	PolicyVersion string `json:"policy_version"`
	CaseID        string `json:"case_id"`
	PreviousHash  string `json:"previous_hash"`
	Hash          string `json:"hash"`
}

func (r Record) Validate() error {
	if r.Version != Version || r.Sequence == 0 || r.Sequence > 9223372036854775807 {
		return errors.New("invalid audit version or sequence")
	}
	for _, id := range []string{r.ChainID, r.ActorID} {
		if !ValidID(id) {
			return errors.New("invalid audit reference")
		}
	}
	if !digestPattern.MatchString(r.PreviousHash) {
		return errors.New("invalid previous digest")
	}
	t, err := time.Parse(TimeLayout, r.OccurredAt)
	if err != nil || t.UTC().Format(TimeLayout) != r.OccurredAt {
		return errors.New("invalid audit timestamp")
	}
	return (Input{EventID: r.EventID, Action: r.Action, ResourceID: r.ResourceID,
		Purpose: r.Purpose, PolicyVersion: r.PolicyVersion, CaseID: r.CaseID}).Validate()
}

// Canonical returns RAC-AUDIT-1, a compact ordered JSON array of strings.
// Sequence is a decimal string to avoid JSON number rounding. No optional field
// disappears; an absent case is the empty string. This is NOT generic RFC 8785.
func (r Record) Canonical() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal([]string{"rac.audit.v1", r.ChainID, strconv.FormatUint(r.Sequence, 10), r.EventID,
		r.OccurredAt, r.ActorID, r.Action, r.ResourceID, r.Purpose, r.PolicyVersion, r.CaseID, r.PreviousHash})
}

func (r Record) Digest() (string, error) {
	b, err := r.Canonical()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func (r Record) VerifyDigest() error {
	h, err := r.Digest()
	if err != nil {
		return err
	}
	if h != r.Hash {
		return fmt.Errorf("audit digest mismatch at sequence %d", r.Sequence)
	}
	return nil
}
