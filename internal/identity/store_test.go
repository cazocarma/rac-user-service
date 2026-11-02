package identity_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	platformidentity "github.com/cazocarma/rac-platform/identity"
	"github.com/cazocarma/rac-user-service/internal/identity"
	"github.com/cazocarma/rac-user-service/internal/identity/fake"
	_ "github.com/lib/pq"
)

func adult(value bool) *bool { return &value }

// TestIdentityVerificationPostgres runs as rac_user against the migrated schema.
func TestIdentityVerificationPostgres(t *testing.T) {
	dsn := os.Getenv("RAC_IDENTITY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated database")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(u.Hostname(), "rac-migration-test-") {
		t.Fatal("isolated fixture required")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	query := u.Query()
	query.Set("options", "-c role=rac_user")
	u.RawQuery = query.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	var run string
	if err = admin.QueryRow(`SELECT substr(md5(random()::text),1,10)`).Scan(&run); err != nil {
		t.Fatal(err)
	}
	// Keycloak subjects are UUIDs; the shared authority only accepts those.
	subjects := map[string]string{}
	subject := func(name string) string { return subjects[name] }
	for _, name := range []string{"a", "b", "minor", "unknown-age", "banned", "f", "g"} {
		var created string
		if err = admin.QueryRow(`INSERT INTO usuario(id,nombre,correo,rol,keycloak_id,email_verified)
 VALUES(gen_random_uuid(),'Synthetic',$1,'cliente',gen_random_uuid()::text,true) RETURNING keycloak_id`,
			"identity-"+run+"-"+name+"@example.test").Scan(&created); err != nil {
			t.Fatal(err)
		}
		subjects[name] = created
	}
	provider, err := fake.New("test", bytes.Repeat([]byte("w"), 32), "http://localhost")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, _ := identity.NewFingerprinter("test-key", bytes.Repeat([]byte("k"), 32))
	service, err := identity.NewService(db, provider, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	events := 0
	event := func() string { events++; return fmt.Sprintf("evt_%s_%04d", run, events) }
	start := func(name string) string {
		t.Helper()
		status, session, err := service.Start(ctx, subject(name), identity.ClientBooking)
		if err != nil || status != identity.Pending || session.URL == "" {
			t.Fatalf("start %s: %s %v", name, status, err)
		}
		return session.ProviderRef
	}
	identityKey := func(label string) []byte { return []byte("provider-identity-" + run + "-" + label) }
	approve := func(ref string, key []byte, isAdult *bool) identity.Result {
		return identity.Result{EventID: event(), ProviderRef: ref, Outcome: identity.Approved, Adult: isAdult,
			DocumentCountry: "CL", IdentityKey: key}
	}

	// Email verification never stands in for identity verification.
	if status, err := service.Current(ctx, subject("a")); err != nil || status != identity.None {
		t.Fatal("verified email produced an identity state", status, err)
	}
	if _, _, err := service.Start(ctx, "00000000-0000-4000-8000-"+run+"00", identity.ClientBooking); !errors.Is(err, identity.ErrNoProfile) {
		t.Fatal("start without profile", err)
	}
	superseded := start("a")
	ref := start("a")
	var expired string
	if err = admin.QueryRow(`SELECT status FROM identity_verifications WHERE provider_ref=$1`, superseded).Scan(&expired); err != nil || expired != "expired" {
		t.Fatal("new attempt did not supersede the pending one", expired, err)
	}
	if _, err := service.Apply(ctx, approve(superseded, identityKey("a"), adult(true))); !errors.Is(err, identity.ErrConflict) {
		t.Fatal("superseded session accepted a result", err)
	}
	accepted := approve(ref, identityKey("a"), adult(true))
	if status, err := service.Apply(ctx, accepted); err != nil || status != identity.Approved {
		t.Fatal("adult approval", status, err)
	}
	if status, err := service.Apply(ctx, accepted); err != nil || status != identity.Approved {
		t.Fatal("replay must be idempotent", status, err)
	}
	if _, err := service.Apply(ctx, identity.Result{EventID: event(), ProviderRef: ref, Outcome: identity.Rejected}); !errors.Is(err, identity.ErrConflict) {
		t.Fatal("decided session changed", err)
	}
	if status, _, err := service.Start(ctx, subject("a"), identity.CompaOnboarding); err != nil || status != identity.Approved {
		t.Fatal("approved person was asked to verify again", status, err)
	}
	if _, err := service.Apply(ctx, approve("fake_unknown_"+run, identityKey("a"), adult(true))); !errors.Is(err, identity.ErrUnknownSession) {
		t.Fatal("unknown session accepted", err)
	}

	decide := func(name string, result func(string) identity.Result, want identity.Status) string {
		t.Helper()
		ref := start(name)
		if status, err := service.Apply(ctx, result(ref)); err != nil || status != want {
			t.Fatalf("%s: got %s %v want %s", name, status, err, want)
		}
		return ref
	}
	decide("b", func(ref string) identity.Result { return approve(ref, identityKey("a"), adult(true)) }, identity.NeedsReview)
	minorRef := decide("minor", func(ref string) identity.Result { return approve(ref, identityKey("minor"), adult(false)) }, identity.Rejected)
	unknownRef := decide("unknown-age", func(ref string) identity.Result { return approve(ref, identityKey("unknown"), nil) }, identity.NeedsReview)
	for _, ref := range []string{minorRef, unknownRef} {
		var stored bool
		if err = admin.QueryRow(`SELECT document_fingerprint IS NOT NULL FROM identity_verifications WHERE provider_ref=$1`, ref).Scan(&stored); err != nil || stored {
			t.Fatal("fingerprint kept without an adult approval", ref, err)
		}
	}
	if _, err = admin.Exec(`INSERT INTO banned_identity_fingerprints(key_id,fingerprint) VALUES('test-key',$1)`,
		fingerprint.Fingerprint("CL", identityKey("banned"))); err != nil {
		t.Fatal(err)
	}
	decide("banned", func(ref string) identity.Result { return approve(ref, identityKey("banned"), adult(true)) }, identity.NeedsReview)

	// Two accounts racing with one identity: exactly one approval.
	refs := map[string]string{"f": start("f"), "g": start("g")}
	results := make(chan identity.Status, 2)
	var wait sync.WaitGroup
	for name := range refs {
		result := approve(refs[name], identityKey("shared"), adult(true))
		wait.Add(1)
		go func() {
			defer wait.Done()
			status, err := service.Apply(ctx, result)
			if err != nil {
				t.Error(err)
			}
			results <- status
		}()
	}
	wait.Wait()
	close(results)
	counts := map[identity.Status]int{}
	for status := range results {
		counts[status]++
	}
	if counts[identity.Approved] != 1 || counts[identity.NeedsReview] != 1 {
		t.Fatal("concurrent duplicate identities", counts)
	}

	// The provider identity key and document data never reach storage.
	var dump string
	if err = admin.QueryRow(`SELECT COALESCE(string_agg(row_to_json(v)::text,''),'') FROM identity_verifications v
 JOIN usuario u ON u.id=v.user_id WHERE u.correo LIKE $1`, "identity-"+run+"-%").Scan(&dump); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"a", "minor", "unknown", "banned", "shared"} {
		key := identityKey(label)
		if strings.Contains(dump, string(key)) || strings.Contains(dump, hex.EncodeToString(key)) {
			t.Fatal("identity key persisted", label)
		}
	}

	// The shared authority reports only approval, for exactly the asked account.
	for name, want := range map[string]bool{"a": true, "b": false, "minor": false, "unknown-age": false, "banned": false} {
		q := platformidentity.Query{AccountID: subject(name), Purpose: platformidentity.ClientBooking}
		o, err := service.ReadIdentity(ctx, q)
		if err != nil || o.Query != q || o.Approved != want || o.ObservedAt.IsZero() {
			t.Fatal("authority read", name, o, err)
		}
		if err := platformidentity.Check(ctx, service, q, time.Second); (err == nil) != want {
			t.Fatal("authority check", name, err)
		}
	}
	if _, err := service.ReadIdentity(ctx, platformidentity.Query{AccountID: "identity-a", Purpose: platformidentity.ClientBooking}); err == nil {
		t.Fatal("non-subject account id accepted")
	}

	// rac_user records results but cannot erase them, rewrite references or ban.
	for _, statement := range []string{
		`DELETE FROM identity_verifications WHERE false`,
		`UPDATE identity_verifications SET provider_ref=provider_ref WHERE false`,
		`UPDATE identity_verifications SET user_id=user_id WHERE false`,
		`INSERT INTO banned_identity_fingerprints(key_id,fingerprint) VALUES('x',decode(repeat('00',32),'hex'))`,
		`SELECT count(*) FROM identity_webhook_events`,
	} {
		if _, err := db.Exec(statement); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("rac_user allowed %q: %v", statement, err)
		}
	}
}
