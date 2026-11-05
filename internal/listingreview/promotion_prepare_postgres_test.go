package listingreview

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/staff"
)

// Reuses the prepared, pending photo of the reader fixture. This proves the
// durable preparation boundary; it does not execute S3 or finalize approval.
func testPromotionPreparationPostgres(t *testing.T, root *sql.DB, dsn string) {
	t.Helper()
	const revision = "aaaaaaaa-0000-4000-8000-000000000001"
	const target = "dddddddd-1111-4111-8111-111111111111"
	const reviewer = "77777777-7777-4777-8777-777777777777"
	const chain = "deaddead-1111-4111-8111-111111111111"
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := root.Exec(statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE ROLE rac_photo_promotion_fixture LOGIN PASSWORD 'synthetic-photo-promotion-only';
 GRANT USAGE ON SCHEMA listing_review,audit TO rac_photo_promotion_fixture;
 GRANT EXECUTE ON FUNCTION listing_review.ready(),` + promotionPrepareSignature + ` TO rac_photo_promotion_fixture;
 INSERT INTO audit.chain_heads(chain_id) VALUES('` + chain + `');
 INSERT INTO audit.writer_principals VALUES('rac_photo_promotion_fixture','feedfeed-1111-4111-8111-111111111111','` + chain + `');
 INSERT INTO photo.media_targets VALUES('` + target + `',decode(repeat('a',64),'hex'),'approved-media-fixture','us-east-1');
 INSERT INTO photo.promotion_policies VALUES('` + fixtureID + `','preview-fixture-1','` + target + `');
 INSERT INTO photo.promotion_gates(policy_version) VALUES('` + fixtureID + `');`)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("rac_photo_promotion_fixture", "synthetic-photo-promotion-only")
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	access, _ := readerAccess(t)
	policy := promotionPolicy{Listing: "fixture-1", Pipeline: "preview-fixture-1", Target: target, Bucket: "approved-media-fixture", Region: "us-east-1", LocatorSHA256: strings.Repeat("a", 64)}
	p, err := newPromotionPreparer(context.Background(), db, access, fixtureID, policy)
	if err != nil {
		t.Fatal("isolated promotion preparer rejected", err)
	}
	if _, err := newPromotionPreparer(context.Background(), root, access, fixtureID, policy); err == nil {
		t.Fatal("superuser accepted as preparer")
	}
	session := staff.Session{Subject: reviewer, Permissions: []staff.Permission{staff.ListingsReview}, AuthenticatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Minute)}
	var hash, versionText string
	var version int64
	if err := root.QueryRow(`SELECT encode(r.payload_hash,'hex'),l.version FROM listing_revisions r JOIN listings l ON l.id=r.listing_id WHERE r.id=$1`, revision).Scan(&hash, &version); err != nil {
		t.Fatal(err)
	}
	versionText = fmt.Sprint(version)
	command := func() approvalCommand {
		id, err := eventID()
		if err != nil {
			t.Fatal(err)
		}
		return approvalCommand{EventID: id, ExpectedVersion: versionText, SHA256: hash}
	}
	counts := func() string {
		var state string
		if err := root.QueryRow(`SELECT (SELECT count(*) FROM photo.promotion_intents)::text||':'||
 (SELECT count(*) FROM photo.promotion_attempts)::text||':'||
 (SELECT count(*) FROM listing_review.access_events WHERE command->>'purpose'='promotion')::text||':'||
 (SELECT count(*) FROM audit.log WHERE chain_id='` + chain + `')::text`).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	if _, err := p.prepare(context.Background(), session, revision, version, command()); err == nil || counts() != "0:0:0:0" {
		t.Fatal("promotion enabled without explicit policy gate", err, counts())
	}
	exec(`UPDATE photo.promotion_gates SET enabled=true WHERE policy_version='` + fixtureID + `'`)
	c := command()
	first, err := p.prepare(context.Background(), session, revision, version, c)
	if err != nil || first.Reused == nil || *first.Reused || counts() != "1:1:1:1" {
		t.Fatal("durable preparation failed", err, counts())
	}
	second, err := p.prepare(context.Background(), session, revision, version, c)
	if err != nil || !*second.Reused || first.ID != second.ID || first.DestinationKey != second.DestinationKey || first.Attempt == second.Attempt || counts() != "1:2:2:2" {
		t.Fatal("retry did not preserve intent/key with fresh audited attempt", err, counts())
	}
	// Another connection can immediately lock the business row: prepare did not
	// leak its transaction to the future storage operation.
	tx, err := root.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT id FROM listings WHERE id='44444444-4444-4444-8444-444444444444' FOR NO KEY UPDATE NOWAIT`); err != nil {
		tx.Rollback()
		t.Fatal("business lock survived prepare", err)
	}
	tx.Rollback()
	for _, statement := range []string{`SELECT * FROM photo.promotion_intents`, `SELECT * FROM photo.promotion_attempts`, `SELECT * FROM photo.media_targets`, `SELECT * FROM photo.promotion_policies`, `SELECT * FROM listing_review.access_events`, `SELECT * FROM listing_revisions`} {
		if _, err := db.Exec(statement); err == nil {
			t.Fatal("function-only preparer gained raw access", statement)
		}
	}
	for _, table := range []string{"photo.promotion_intents", "photo.promotion_attempts", "photo.media_targets", "photo.promotion_policies"} {
		for _, statement := range []string{"UPDATE " + table + " SET " + map[string]string{"photo.promotion_intents": "listing_policy=listing_policy", "photo.promotion_attempts": "expires_at=expires_at", "photo.media_targets": "bucket_name=bucket_name", "photo.promotion_policies": "pipeline_version=pipeline_version"}[table], "DELETE FROM " + table} {
			if _, err := root.Exec(statement); err == nil {
				t.Fatal("immutable preparation history changed", statement)
			}
		}
	}
	before := counts()
	other := session
	other.Subject = "88888888-8888-4888-8888-888888888888"
	if _, err := p.prepare(context.Background(), other, revision, version, c); err == nil || counts() != before {
		t.Fatal("another human reused the intent", err)
	}
	changed := c
	changed.SHA256 = strings.Repeat("f", 64)
	if _, err := p.prepare(context.Background(), session, revision, version, changed); err == nil || counts() != before {
		t.Fatal("changed command reused intent", err)
	}
	for _, change := range []func(*promotionPreparer){
		func(p *promotionPreparer) { p.policy.Listing = "other-1" }, func(p *promotionPreparer) { p.policy.Pipeline = "other-1" },
		func(p *promotionPreparer) { p.policy.Target = "eeeeeeee-1111-4111-8111-111111111111" },
	} {
		altered := *p
		change(&altered)
		if _, err := altered.prepare(context.Background(), session, revision, version, c); err == nil || counts() != before {
			t.Fatal("policy/target conflict reused intent", err)
		}
	}
	self := session
	self.Subject = fixtureID
	if _, err := p.prepare(context.Background(), self, revision, version, command()); err == nil || counts() != before {
		t.Fatal("owner prepared self approval", err)
	}
	exec(`UPDATE photo.promotion_gates SET enabled=false WHERE policy_version='` + fixtureID + `'`)
	if _, err := p.prepare(context.Background(), session, revision, version, c); err == nil || counts() != before {
		t.Fatal("disabled policy allowed retry I/O", err)
	}
	exec(`UPDATE photo.promotion_gates SET enabled=true WHERE policy_version='` + fixtureID + `'`)
	// Expiry after the SQL call rolls back intent, attempt and audit together.
	calls := 0
	p.owner.now = func() time.Time {
		calls++
		if calls == 1 {
			return time.Now()
		}
		return time.Now().Add(24 * time.Hour)
	}
	if _, err := p.prepare(context.Background(), session, revision, version, command()); err == nil || counts() != before {
		t.Fatal("expired MFA committed preparation", err, counts())
	}
	p.owner.now = time.Now
	exec(`CREATE FUNCTION listing_review.promotion_fixture_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.command->>'purpose'='promotion' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER promotion_fixture_failure BEFORE INSERT ON listing_review.access_events FOR EACH ROW EXECUTE FUNCTION listing_review.promotion_fixture_failure();`)
	if _, err := p.prepare(context.Background(), session, revision, version, command()); err == nil || counts() != before {
		t.Fatal("audit fault left partial intent", err, counts())
	}
	exec(`DROP TRIGGER promotion_fixture_failure ON listing_review.access_events; DROP FUNCTION listing_review.promotion_fixture_failure();`)
	// Two replicas receive the same durable intent/key, but distinct access
	// attempts; the event advisory lock serializes creation.
	concurrent := command()
	results := make(chan promotionIntent, 2)
	failures := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			value, err := p.prepare(context.Background(), session, revision, version, concurrent)
			results <- value
			failures <- err
		}()
	}
	group.Wait()
	for range 2 {
		if err := <-failures; err != nil {
			t.Fatal("concurrent prepare failed", err)
		}
	}
	a, b := <-results, <-results
	if a.ID != b.ID || a.Attempt == b.Attempt || a.DestinationKey != b.DestinationKey || counts() != "2:4:4:4" {
		t.Fatal("concurrent prepare split intent or lost audit", counts())
	}
	before = counts()
	exec(`UPDATE listings SET version=version+1 WHERE id='44444444-4444-4444-8444-444444444444'`)
	if _, err := p.prepare(context.Background(), session, revision, version, c); err == nil || counts() != before {
		t.Fatal("stale listing prepared copy", err)
	}
	var published bool
	if err := root.QueryRow(`SELECT published_revision_id IS NOT NULL OR state<>'unpublished' FROM listings WHERE id='44444444-4444-4444-8444-444444444444'`).Scan(&published); err != nil || published {
		t.Fatal("preparation published a listing", err)
	}
}
