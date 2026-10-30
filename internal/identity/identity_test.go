package identity

import (
	"bytes"
	"strings"
	"testing"
)

func flag(value bool) *bool { return &value }

func TestDecideNeverBansOrApprovesWithoutAdultProof(t *testing.T) {
	approved := Result{Outcome: Approved, Adult: flag(true)}
	for _, test := range []struct {
		name              string
		result            Result
		banned, duplicate bool
		want              Status
	}{
		{"adult", approved, false, false, Approved},
		{"minor", Result{Outcome: Approved, Adult: flag(false)}, false, false, Rejected},
		{"undetermined age", Result{Outcome: Approved}, false, false, NeedsReview},
		{"banned fingerprint", approved, true, false, NeedsReview},
		{"other account", approved, false, true, NeedsReview},
		{"provider rejection", Result{Outcome: Rejected, Adult: flag(true)}, false, false, Rejected},
		{"expired", Result{Outcome: Expired}, false, false, Expired},
		{"provider review", Result{Outcome: NeedsReview, Adult: flag(true)}, false, false, NeedsReview},
		{"unknown outcome", Result{Outcome: "approved_by_timeout", Adult: flag(true)}, false, false, NeedsReview},
	} {
		if got := Decide(test.result, test.banned, test.duplicate); got != test.want {
			t.Errorf("%s: got %s want %s", test.name, got, test.want)
		}
	}
}

func TestResultValidation(t *testing.T) {
	valid := Result{EventID: "evt_00000001", ProviderRef: "fake_00000001", Outcome: Approved, Adult: flag(true),
		DocumentCountry: "CL", IdentityKey: bytes.Repeat([]byte{7}, 16)}
	if valid.Validate() != nil {
		t.Fatal("valid result rejected")
	}
	for name, mutate := range map[string]func(*Result){
		"short event":       func(r *Result) { r.EventID = "evt" },
		"spaced ref":        func(r *Result) { r.ProviderRef = "fake 00000001" },
		"pending outcome":   func(r *Result) { r.Outcome = Pending },
		"lowercase country": func(r *Result) { r.DocumentCountry = "cl" },
		"missing key":       func(r *Result) { r.IdentityKey = nil },
		"short key":         func(r *Result) { r.IdentityKey = []byte("short") },
		"huge key":          func(r *Result) { r.IdentityKey = bytes.Repeat([]byte{1}, 257) },
	} {
		candidate := valid
		mutate(&candidate)
		if candidate.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	rejected := Result{EventID: "evt_00000002", ProviderRef: "fake_00000002", Outcome: Rejected}
	if rejected.Validate() != nil {
		t.Fatal("rejection without document data refused")
	}
}

func TestFingerprintIsKeyedAndDomainSeparated(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	first, err := NewFingerprinter("k2026-10", key)
	if err != nil {
		t.Fatal(err)
	}
	identityKey := []byte("provider-stable-identity-0001")
	value := first.Fingerprint("CL", identityKey)
	if len(value) != 32 || !bytes.Equal(value, first.Fingerprint("CL", identityKey)) {
		t.Fatal("fingerprint must be a stable 32-byte HMAC")
	}
	other, _ := NewFingerprinter("k2026-11", bytes.Repeat([]byte{2}, 32))
	if bytes.Equal(value, other.Fingerprint("CL", identityKey)) {
		t.Fatal("different keys produced the same fingerprint")
	}
	if bytes.Equal(value, first.Fingerprint("AR", identityKey)) {
		t.Fatal("country is not part of the fingerprint")
	}
	// The separator prevents country/key boundary shifts from colliding.
	if bytes.Equal(first.Fingerprint("CL", []byte("Xabc")), first.Fingerprint("CLX", []byte("abc"))) {
		t.Fatal("ambiguous fingerprint encoding")
	}
	if strings.Contains(string(value), string(identityKey)) {
		t.Fatal("identity key leaked into fingerprint")
	}
	for _, bad := range []struct {
		id  string
		key []byte
	}{{"", key}, {"Upper", key}, {"k1", key[:31]}} {
		if _, err := NewFingerprinter(bad.id, bad.key); err == nil {
			t.Errorf("accepted fingerprint key %q/%d", bad.id, len(bad.key))
		}
	}
}
