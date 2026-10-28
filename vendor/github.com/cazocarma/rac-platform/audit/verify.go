package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
)

// Head is a trust input. Comparing only a file's self-reported head does not
// detect an attacker rewriting that file and its chain together.
type Head struct {
	ChainID  string `json:"chain_id"`
	Sequence uint64 `json:"sequence"`
	Hash     string `json:"hash"`
}

func (h Head) Validate() error {
	if !ValidID(h.ChainID) || h.Sequence > 9223372036854775807 || !digestPattern.MatchString(h.Hash) || (h.Sequence == 0 && h.Hash != ZeroHash) {
		return errors.New("invalid audit head")
	}
	return nil
}

// Verify checks a contiguous range against BOTH a trusted predecessor and a
// trusted end head. Requiring the end head detects a missing final record.
func Verify(records []Record, predecessor, expected Head) error {
	if err := predecessor.Validate(); err != nil {
		return err
	}
	if err := expected.Validate(); err != nil {
		return err
	}
	if predecessor.ChainID != expected.ChainID || predecessor.Sequence > expected.Sequence {
		return errors.New("invalid audit range")
	}
	head := predecessor
	for _, r := range records {
		if r.ChainID != head.ChainID || r.Sequence != head.Sequence+1 || r.PreviousHash != head.Hash {
			return errors.New("audit continuity failure")
		}
		if err := r.VerifyDigest(); err != nil {
			return err
		}
		head = Head{r.ChainID, r.Sequence, r.Hash}
	}
	if head != expected {
		return errors.New("audit end head mismatch or truncated range")
	}
	return nil
}

// VerifyStream does not retain a potentially sensitive unbounded export in
// memory. Unknown fields and a second JSON value on a record are rejected.
func VerifyStream(input io.Reader, predecessor, expected Head) error {
	if err := predecessor.Validate(); err != nil {
		return err
	}
	if err := expected.Validate(); err != nil {
		return err
	}
	if predecessor.ChainID != expected.ChainID || predecessor.Sequence > expected.Sequence {
		return errors.New("invalid audit range")
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 1024), 4096)
	head := predecessor
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var r Record
		var err error
		r, err = decodeRecord(line)
		if err != nil {
			return err
		}
		next := Head{r.ChainID, r.Sequence, r.Hash}
		if err := Verify([]Record{r}, head, next); err != nil {
			return err
		}
		head = next
	}
	if scanner.Err() != nil {
		return errors.New("audit stream unreadable or record exceeds 4096 bytes")
	}
	if head != expected {
		return errors.New("audit end head mismatch or truncated range")
	}
	return nil
}

// Reject duplicate/case-folded keys as well as unknown fields: encoding/json's
// default last-key-wins behavior could otherwise hide private extra values in
// an export whose decoded record appears to satisfy the metadata contract.
func decodeRecord(line []byte) (Record, error) {
	var r Record
	invalid := errors.New("invalid audit JSON stream")
	dec := json.NewDecoder(bytes.NewReader(line))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return r, invalid
	}
	seen := make(map[string]bool, 13)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return r, invalid
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return r, invalid
		}
		seen[key] = true
		var dest any
		switch key {
		case "version":
			dest = &r.Version
		case "chain_id":
			dest = &r.ChainID
		case "sequence":
			dest = &r.Sequence
		case "event_id":
			dest = &r.EventID
		case "occurred_at":
			dest = &r.OccurredAt
		case "actor_id":
			dest = &r.ActorID
		case "action":
			dest = &r.Action
		case "resource_id":
			dest = &r.ResourceID
		case "purpose":
			dest = &r.Purpose
		case "policy_version":
			dest = &r.PolicyVersion
		case "case_id":
			dest = &r.CaseID
		case "previous_hash":
			dest = &r.PreviousHash
		case "hash":
			dest = &r.Hash
		default:
			return r, invalid
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil || bytes.Equal(value, []byte("null")) || json.Unmarshal(value, dest) != nil {
			return r, invalid
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 13 {
		return r, invalid
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return r, invalid
	}
	return r, nil
}

// Checkpoint binds a head and a key identifier with an Ed25519 signature.
// Trust and custody of public keys must be independent of the export being
// checked. No key is generated, stored or activated automatically here.
type Checkpoint struct {
	Head      Head   `json:"head"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

func checkpointBytes(h Head, keyID string) ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	if !ValidID(keyID) {
		return nil, errors.New("invalid checkpoint key reference")
	}
	return json.Marshal([]string{"rac.audit.checkpoint.v1", h.ChainID, strconv.FormatUint(h.Sequence, 10), h.Hash, keyID})
}

func SignHead(h Head, keyID string, key ed25519.PrivateKey) (Checkpoint, error) {
	b, err := checkpointBytes(h, keyID)
	if err != nil {
		return Checkpoint{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return Checkpoint{}, errors.New("invalid signing key")
	}
	return Checkpoint{h, keyID, base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))}, nil
}

func (c Checkpoint) Verify(key ed25519.PublicKey) error {
	b, err := checkpointBytes(c.Head, c.KeyID)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(c.Signature)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, b, sig) {
		return errors.New("invalid audit checkpoint signature")
	}
	return nil
}
