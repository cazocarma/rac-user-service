package listingreview

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/staff"
	"github.com/cazocarma/rac-user-service/internal/listings"
	"github.com/cazocarma/rac-user-service/internal/photostore"
	"github.com/lib/pq"
)

// Builds on the prepared photo/registry fixtures, retaining the real scoped
// LOGIN and DB constraints. Prerequisite policy is synthetic, not legal approval.
func testPhotoFinalizationPostgres(t *testing.T, root *sql.DB, dsn string) {
	t.Helper()
	const listing = "44444444-4444-4444-8444-444444444444"
	const owner = "22222222-2222-4222-8222-222222222222"
	const target = "dddddddd-1111-4111-8111-111111111111"
	const actor = "77777777-7777-4777-8777-777777777777"
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := root.Exec(statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE ROLE rac_photo_finalizer_fixture LOGIN PASSWORD 'synthetic-photo-finalizer-only';
 GRANT USAGE ON SCHEMA listing_review,audit TO rac_photo_finalizer_fixture;
 GRANT EXECUTE ON FUNCTION ` + joinPhotoSignatures() + ` TO rac_photo_finalizer_fixture;
 INSERT INTO audit.chain_heads(chain_id) VALUES('abcddcba-2222-4222-8222-222222222222');
 INSERT INTO audit.writer_principals VALUES('rac_photo_finalizer_fixture','abcddcba-3333-4333-8333-333333333333','abcddcba-2222-4222-8222-222222222222');`)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("rac_photo_finalizer_fixture", "synthetic-photo-finalizer-only")
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	policy := promotionPolicy{Listing: "fixture-1", Pipeline: "preview-fixture-1", Target: target}
	if err := root.QueryRow(`SELECT bucket_name,region,encode(locator_sha256,'hex') FROM photo.media_targets WHERE id=$1`, target).Scan(&policy.Bucket, &policy.Region, &policy.LocatorSHA256); err != nil {
		t.Fatal(err)
	}
	data := reviewFixtureJPEG(t)
	var calls atomic.Int64
	var onSource func()
	var source PreviewStore = previewFixtureStore{get: func(context.Context, string) ([]byte, error) { return bytes.Clone(data), nil }}
	var destination promotionDestination
	var mutex sync.Mutex
	objects := map[string][]byte{}
	destination = copyFixtureDestination{
		create: func(_ context.Context, key string, raw []byte) (string, error) {
			mutex.Lock()
			defer mutex.Unlock()
			if _, exists := objects[key]; exists {
				return "", photostore.ErrExists
			}
			objects[key] = bytes.Clone(raw)
			return "fixture-version-1", nil
		},
		current: func(context.Context, string) (string, error) { return "fixture-version-1", nil },
		version: func(_ context.Context, key, version string) ([]byte, error) {
			mutex.Lock()
			defer mutex.Unlock()
			if version != "fixture-version-1" {
				return nil, errors.New("wrong fixture version")
			}
			return bytes.Clone(objects[key]), nil
		},
	}
	if endpoint := os.Getenv("RAC_PHOTO_PIPELINE_TEST_ENDPOINT"); endpoint != "" {
		source, err = photostore.NewS3Reader(endpoint, "us-east-1", os.Getenv("PHOTO_STAGING_BUCKET"), os.Getenv("PHOTO_PROMOTER_ACCESS_KEY"), os.Getenv("PHOTO_PROMOTER_SECRET_KEY"))
		if err != nil {
			t.Fatal(err)
		}
		destination, err = photostore.NewVersionedS3(endpoint, "us-east-1", policy.Bucket, os.Getenv("PHOTO_PROMOTER_ACCESS_KEY"), os.Getenv("PHOTO_PROMOTER_SECRET_KEY"))
		if err != nil {
			t.Fatal(err)
		}
	}
	actualSource, actualDestination := source, destination
	source = previewFixtureStore{get: func(ctx context.Context, key string) ([]byte, error) {
		calls.Add(1)
		if onSource != nil {
			onSource()
		}
		return actualSource.Get(ctx, key)
	}}
	destination = copyFixtureDestination{
		create: func(ctx context.Context, key string, raw []byte) (string, error) {
			calls.Add(1)
			return actualDestination.Create(ctx, key, raw)
		},
		current: func(ctx context.Context, key string) (string, error) {
			calls.Add(1)
			return actualDestination.CurrentVersion(ctx, key)
		},
		version: func(ctx context.Context, key, version string) ([]byte, error) {
			calls.Add(1)
			return actualDestination.Version(ctx, key, version)
		},
	}
	var deny atomic.Bool
	check := func(ctx context.Context, tx *sql.Tx, subject string) (listings.Checked, error) {
		if subject != fixtureID {
			t.Fatal("wrong profile owner")
		}
		if deny.Load() {
			return listings.Checked{}, listings.ErrPrerequisites
		}
		if _, err := tx.ExecContext(ctx, `SELECT id FROM usuario WHERE keycloak_id=$1 FOR KEY SHARE`, subject); err != nil {
			return listings.Checked{}, err
		}
		return listings.Checked{Documents: true, Identity: false}, nil
	}
	access, token := readerAccess(t)
	a, err := newPhotoApprover(context.Background(), db, root, access, fixtureID, policy, true, check, source, destination)
	if err != nil {
		t.Fatal("isolated photo coordinator refused", err)
	}
	if !a.owner.isReady(context.Background()) {
		t.Fatal("registered promotion policy not ready")
	}
	exec(`UPDATE photo.promotion_gates SET enabled=false WHERE policy_version='` + fixtureID + `'`)
	if a.owner.isReady(context.Background()) {
		t.Fatal("retired promotion policy remained ready")
	}
	if _, err := newPhotoApprover(context.Background(), db, root, access, fixtureID, policy, true, check, source, destination); err == nil {
		t.Fatal("constructor accepted disabled promotion policy")
	}
	exec(`UPDATE photo.promotion_gates SET enabled=true WHERE policy_version='` + fixtureID + `'`)
	wrong := policy
	wrong.Bucket = "different-private-media"
	if _, err := newPhotoApprover(context.Background(), db, root, access, fixtureID, wrong, true, check, source, destination); err == nil {
		t.Fatal("constructor accepted different physical target")
	}
	session := staff.Session{Subject: actor, Permissions: []staff.Permission{staff.ListingsReview}, AuthenticatedAt: time.Now().Add(-30 * time.Second), ExpiresAt: time.Now().Add(3 * time.Minute)}
	pending := func() (string, int64, approvalCommand) {
		t.Helper()
		revision, err := eventID()
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO listing_revisions(id,listing_id,revision_no,payload_canonical,assessment,risk_score,policy_version)
 SELECT $1,$2,COALESCE(max(revision_no),0)+1,'{"activities":[{"slug":"cine","note":""}],"description":"Synthetic approved photo","photo_version":"bbbbbbbb-0000-4000-8000-000000000001"}','{}',0,'fixture-1' FROM listing_revisions WHERE listing_id=$2`, revision, listing)
		var version int64
		if err := root.QueryRow(`UPDATE listings SET pending_revision_id=$1,version=version+1 WHERE id=$2 RETURNING version`, revision, listing).Scan(&version); err != nil {
			t.Fatal(err)
		}
		var hash string
		if err := root.QueryRow(`SELECT encode(payload_hash,'hex') FROM listing_revisions WHERE id=$1`, revision).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		event, err := eventID()
		if err != nil {
			t.Fatal(err)
		}
		return revision, version, approvalCommand{EventID: event, ExpectedVersion: fmt.Sprint(version), SHA256: hash}
	}
	state := func() string {
		var s string
		if err := root.QueryRow(`SELECT
 (SELECT count(*) FROM photo.promotion_receipts pr JOIN photo.promotion_intents pi ON pi.id=pr.intent_id WHERE pi.database_role='rac_photo_finalizer_fixture')::text||':'||
 (SELECT count(*) FROM photo.approved_references ar JOIN photo.promotion_intents pi ON pi.id=ar.intent_id WHERE pi.database_role='rac_photo_finalizer_fixture')::text||':'||
 (SELECT count(*) FROM listing_review.decision_events WHERE database_role='rac_photo_finalizer_fixture')::text||':'||
 (SELECT count(*) FROM listing_review.outbox o JOIN listing_review.decision_events e ON e.event_id=o.event_id WHERE e.database_role='rac_photo_finalizer_fixture')::text||':'||
 (SELECT COALESCE(published_revision_id::text,'none') FROM listings WHERE id='` + listing + `')`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	prepareCopy := func(revision string, version int64, c approvalCommand) (promotionIntent, promotionCopyReceipt) {
		t.Helper()
		intent, err := a.preparer.prepare(context.Background(), session, revision, version, c)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := copyPreparedPhoto(context.Background(), session, intent, source, destination, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		return intent, receipt
	}
	revision, version, c := pending()
	result, err := a.approve(context.Background(), session, revision, version, c)
	if err != nil || !validPhotoApprovalResult(result, revision, c.EventID) || state() != "1:1:1:1:"+revision {
		t.Fatal("atomic photo approval failed", err, state())
	}
	before, beforeCalls := state(), calls.Load()
	replay, err := a.approve(context.Background(), session, revision, version, c)
	if err != nil || !bytes.Equal(result, replay) || state() != before || calls.Load() != beforeCalls {
		t.Fatal("lost commit ACK replay copied or changed effects", err, state())
	}
	other := session
	other.Subject = "88888888-8888-4888-8888-888888888888"
	if _, err := a.approve(context.Background(), other, revision, version, c); err == nil || state() != before || calls.Load() != beforeCalls {
		t.Fatal("other reviewer reused finalized event", err)
	}
	for _, statement := range []string{`SELECT * FROM photo.promotion_receipts`, `SELECT * FROM photo.approved_references`, `SELECT * FROM listing_revision_decisions`} {
		if _, err := db.Exec(statement); err == nil {
			t.Fatal("photo approver read raw table", statement)
		}
	}
	for _, table := range []string{"photo.promotion_receipts", "photo.approved_references"} {
		if _, err := root.Exec("DELETE FROM " + table); err == nil {
			t.Fatal("approved media history deleted", table)
		}
	}
	// Requirement change after the copy retains a private object, but no receipt,
	// decision, outbox or pointer is committed.
	revision, version, c = pending()
	before = state()
	deny.Store(true)
	beforeCalls = calls.Load()
	if _, err := a.approve(context.Background(), session, revision, version, c); !errors.Is(err, listings.ErrPrerequisites) || state() != before || calls.Load() == beforeCalls {
		t.Fatal("prerequisite change published or never exercised copy", err, state())
	}
	deny.Store(false)
	for _, kind := range []string{"policy", "standing", "catalog"} {
		revision, version, c = pending()
		before = state()
		onSource = func() {
			switch kind {
			case "policy":
				exec(`UPDATE photo.promotion_gates SET enabled=false WHERE policy_version='` + fixtureID + `'`)
			case "standing":
				exec(`UPDATE standing.account SET status='suspended' WHERE subject_id='` + owner + `'`)
			case "catalog":
				exec(`UPDATE activity_categories SET status='retired' WHERE slug='cine'`)
			}
		}
		if _, err := a.approve(context.Background(), session, revision, version, c); err == nil || state() != before {
			t.Fatal("changed authorization during storage published", kind, err, state())
		}
		onSource = nil
		exec(`UPDATE photo.promotion_gates SET enabled=true WHERE policy_version='` + fixtureID + `'; UPDATE standing.account SET status='active' WHERE subject_id='` + owner + `'; UPDATE activity_categories SET status='active' WHERE slug='cine';`)
	}
	// Late outbox fault must roll back the receipt, reference and public pointer.
	revision, version, c = pending()
	before = state()
	exec(`CREATE FUNCTION listing_review.photo_final_fixture_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic photo outbox failure'; END $$;
 REVOKE ALL ON FUNCTION listing_review.photo_final_fixture_failure() FROM PUBLIC;
 CREATE TRIGGER photo_final_fixture_failure BEFORE INSERT ON listing_review.outbox FOR EACH ROW EXECUTE FUNCTION listing_review.photo_final_fixture_failure();`)
	_, err = a.approve(context.Background(), session, revision, version, c)
	var pg *pq.Error
	if !errors.As(err, &pg) || pg.Message != "synthetic photo outbox failure" || state() != before {
		t.Fatal("late outbox fault left effects or was not reached", err, state())
	}
	exec(`DROP TRIGGER photo_final_fixture_failure ON listing_review.outbox; DROP FUNCTION listing_review.photo_final_fixture_failure();`)
	// Go's final MFA boundary rolls back an already executed SQL command.
	revision, version, c = pending()
	intent, receipt := prepareCopy(revision, version, c)
	before = state()
	ticks := 0
	a.owner.now = func() time.Time {
		ticks++
		if ticks == 1 {
			return time.Now()
		}
		return time.Now().Add(24 * time.Hour)
	}
	if _, err := a.finalize(context.Background(), session, intent, receipt, c); err == nil || state() != before {
		t.Fatal("late MFA expiry published", err, state())
	}
	a.owner.now = time.Now
	// DB-clock expiry is checked at COMMIT even without the Go boundary.
	revision, version, c = pending()
	intent, receipt = prepareCopy(revision, version, c)
	before = state()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	var raw []byte
	if err := tx.QueryRow(`SELECT listing_review.finalize_photo_promotion($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		c.EventID, session.Subject, fixtureID, revision, version, c.SHA256, policy.Listing, `{"documents":true,"identity":false,"allow_proposed_activities":true}`, true,
		intent.ID, intent.Attempt, receipt.version, receipt.digest[:], receipt.size, until.UTC()).Scan(&raw); err != nil {
		tx.Rollback()
		t.Fatal("commit-expiry fixture did not stage approval", err)
	}
	time.Sleep(time.Until(until) + 30*time.Millisecond)
	if err := tx.Commit(); !errors.As(err, &pg) || pg.Message != "listing_photo_authorization_expired" || state() != before {
		t.Fatal("deferred deadline did not roll back full approval", err, state())
	}
	// Two commands/people may copy privately; only one can publish the version.
	revision, version, c = pending()
	first, firstReceipt := prepareCopy(revision, version, c)
	secondCommand := c
	secondCommand.EventID, _ = eventID()
	second, err := a.preparer.prepare(context.Background(), other, revision, version, secondCommand)
	if err != nil {
		t.Fatal(err)
	}
	secondReceipt, err := copyPreparedPhoto(context.Background(), other, second, source, destination, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	results := make(chan error, 2)
	group.Add(2)
	go func() {
		defer group.Done()
		_, err := a.finalize(context.Background(), session, first, firstReceipt, c)
		results <- err
	}()
	go func() {
		defer group.Done()
		_, err := a.finalize(context.Background(), other, second, secondReceipt, secondCommand)
		results <- err
	}()
	group.Wait()
	winners := 0
	for range 2 {
		if err := <-results; err == nil {
			winners++
		}
	}
	if winners != 1 || state() != "2:2:2:2:"+revision {
		t.Fatal("concurrent photo approval did not have one atomic winner", winners, state())
	}
	// Receipt retains the processor digest and a real/fixture non-null version.
	var digest, providerVersion string
	if err := root.QueryRow(`SELECT encode(pr.normalized_sha256,'hex'),pr.version_id FROM photo.promotion_receipts pr JOIN photo.promotion_intents pi ON pi.id=pr.intent_id WHERE pi.revision_id=$1`, revision).Scan(&digest, &providerVersion); err != nil || digest != hex.EncodeToString(firstReceipt.digest[:]) || !photostore.ValidVersionID(providerVersion) {
		t.Fatal("wrong persisted media receipt", err)
	}
	if os.Getenv("RAC_PHOTO_PIPELINE_TEST_ENDPOINT") != "" {
		t.Run("rustfs-complete-no-recopy", func(t *testing.T) {
			revision, version, c := pending()
			result, err := a.approve(context.Background(), session, revision, version, c)
			if err != nil || !validPhotoApprovalResult(result, revision, c.EventID) || state() != "3:3:3:3:"+revision {
				t.Fatal("real RustFS atomic photo approval failed", err, state())
			}
			count := calls.Load()
			prior, err := a.approve(context.Background(), session, revision, version, c)
			if err != nil || !bytes.Equal(prior, result) || count != calls.Load() || state() != "3:3:3:3:"+revision {
				t.Fatal("real completed replay touched storage or duplicated effects", err, state())
			}
		})
	}
	t.Run("staff-http", func(t *testing.T) {
		revision, _, command := pending()
		body, err := json.Marshal(command)
		if err != nil {
			t.Fatal(err)
		}
		path := "/internal/listings/revisions/" + revision + "/photo-approval"
		handler := a.Handler()
		call := func(path string, body []byte, credential string) *httptest.ResponseRecorder {
			r := httptest.NewRequest("POST", path, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			if credential != "" {
				r.Header.Set("Authorization", "Bearer "+credential)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			return w
		}
		before := calls.Load()
		for _, auth := range []string{"", token("support", staff.ListingsAudience, actor), token("ts_agent", staff.AdminAudience, actor)} {
			w := call(path, body, auth)
			if w.Code != 401 && w.Code != 403 {
				t.Fatal("private HTTP authorization bypass", w.Code)
			}
		}
		auth := token("ts_agent", staff.ListingsAudience, actor)
		for _, invalid := range []string{`{"event_id":"invalid"}`, string(body[:len(body)-1]) + `,"actor":"forged"}`} {
			if w := call(path, []byte(invalid), auth); w.Code != 400 {
				t.Fatal("asserted HTTP authority accepted", w.Code)
			}
		}
		if calls.Load() != before {
			t.Fatal("unauthorized request read/wrote storage")
		}
		w := call(path, body, auth)
		if w.Code != 200 || !validPhotoApprovalResult(w.Body.Bytes(), revision, command.EventID) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("verified JWT HTTP approval failed", w.Code, w.Body.String())
		}
		published := state()
		copied := calls.Load()
		prior := call(path, body, auth)
		if prior.Code != 200 || !bytes.Equal(prior.Body.Bytes(), w.Body.Bytes()) || state() != published || calls.Load() != copied {
			t.Fatal("HTTP finalized replay copied or duplicated effects", prior.Code)
		}
		readerURL := *u
		readerURL.User = url.UserPassword("rac_listing_reader_fixture", "synthetic-reader-only-123456")
		readerDB, err := sql.Open("postgres", readerURL.String())
		if err != nil {
			t.Fatal(err)
		}
		defer readerDB.Close()
		capabilities, err := New(context.Background(), readerDB, access, fixtureID)
		if err != nil {
			t.Fatal(err)
		}
		get := func() *httptest.ResponseRecorder {
			r := httptest.NewRequest("GET", "/internal/listings/capabilities", nil)
			r.Header.Set("Authorization", "Bearer "+auth)
			w := httptest.NewRecorder()
			capabilities.Handler().ServeHTTP(w, r)
			return w
		}
		if w := get(); w.Code != 200 || w.Body.String() != "{\"photo_approval_enabled\":false}\n" {
			t.Fatal("capability enabled without configured coordinator", w.Code, w.Body.String())
		}
		capabilities.promotionReady = a.owner.isReady
		if w := get(); w.Code != 200 || w.Body.String() != "{\"photo_approval_enabled\":true}\n" {
			t.Fatal("ready capability missing", w.Code, w.Body.String())
		}
		exec(`UPDATE photo.promotion_gates SET enabled=false WHERE policy_version='` + fixtureID + `'`)
		if w := get(); w.Code != 200 || w.Body.String() != "{\"photo_approval_enabled\":false}\n" {
			t.Fatal("capability stayed enabled after policy retirement", w.Code, w.Body.String())
		}
		exec(`UPDATE photo.promotion_gates SET enabled=true WHERE policy_version='` + fixtureID + `'`)
	})
}

func joinPhotoSignatures() string { return strings.Join(photoApprovalSignatures, ",") }
