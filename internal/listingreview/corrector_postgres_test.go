package listingreview

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cazocarma/rac-platform/staff"
)

func TestCorrectionPostgresHTTP(t *testing.T) {
	dsn := os.Getenv("RAC_LISTING_CORRECTION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated correction database")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(u.Hostname(), "rac-migration-test-") || u.Path != "/listing_corrector_http" {
		t.Fatal("refusing non-disposable correction database")
	}
	root, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	exec := func(statement string) {
		t.Helper()
		if _, err := root.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	const reviewer = "77777777-7777-4777-8777-777777777777"
	const currentRevision = "66666666-6666-4666-8666-666666666666"
	exec(`CREATE ROLE rac_listing_corrector_fixture LOGIN PASSWORD 'synthetic-corrector-only-123456';
 GRANT USAGE ON SCHEMA listing_review,audit TO rac_listing_corrector_fixture;
 GRANT EXECUTE ON FUNCTION ` + strings.Join(correctionSignatures, ",") + ` TO rac_listing_corrector_fixture;
 INSERT INTO audit.chain_heads(chain_id) VALUES('88888888-8888-4888-8888-888888888888');
 INSERT INTO audit.writer_principals VALUES('rac_listing_corrector_fixture','99999999-9999-4999-8999-999999999999','88888888-8888-4888-8888-888888888888');
 INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) VALUES('22222222-2222-4222-8222-222222222222','Correction fixture','correction@example.test','compa','` + fixtureID + `');
 INSERT INTO compa_perfil(id,usuario_id,descripcion,tarifa_hora) VALUES('33333333-3333-4333-8333-333333333333','22222222-2222-4222-8222-222222222222','Synthetic',12000);
 INSERT INTO listings(id,compa_id) VALUES('44444444-4444-4444-8444-444444444444','33333333-3333-4333-8333-333333333333');
 INSERT INTO listing_revisions(id,listing_id,revision_no,payload_canonical,assessment,risk_score,policy_version)
 VALUES('55555555-5555-4555-8555-555555555555','44444444-4444-4444-8444-444444444444',1,'{"description":"Historical approved fixture"}','{}',0,'fixture-1');
 UPDATE listings SET pending_revision_id='55555555-5555-4555-8555-555555555555',version=version+1 WHERE id='44444444-4444-4444-8444-444444444444';
 BEGIN;
 INSERT INTO listing_revision_decisions(revision_id,action,reviewer_subject,reason_code,note_to_user_key)
 VALUES('55555555-5555-4555-8555-555555555555','approved','historical-fixture','fixture_approval','listingApproved');
 UPDATE listings SET state='published',published_revision_id='55555555-5555-4555-8555-555555555555',pending_revision_id=NULL,version=version+1 WHERE id='44444444-4444-4444-8444-444444444444';
 COMMIT;`)
	// A superuser seeds a historical schema-only approval. No application
	// approval or real human/legal decision is inferred from this fixture.
	addPending := func(id string, number int) {
		t.Helper()
		exec(fmt.Sprintf(`
 INSERT INTO listing_revisions(id,listing_id,revision_no,payload_canonical,assessment,risk_score,policy_version)
 VALUES('%s','44444444-4444-4444-8444-444444444444',%d,'{"description":"Private synthetic candidate"}','{"signals":["private-synthetic-signal"]}',20,'fixture-1');
 UPDATE listings SET pending_revision_id='%s',version=version+1 WHERE id='44444444-4444-4444-8444-444444444444';`, id, number, id))
	}
	addPending(currentRevision, 2)
	u.User = url.UserPassword("rac_listing_corrector_fixture", "synthetic-corrector-only-123456")
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	access, token := readerAccess(t)
	corrector, err := NewCorrector(context.Background(), db, access, fixtureID)
	if err != nil {
		t.Fatal("scoped corrector rejected", err)
	}
	if _, err := New(context.Background(), db, access, fixtureID); err == nil {
		t.Fatal("writer accepted as reader")
	}
	if _, err := db.Exec(`SELECT * FROM listing_review.decision_events`); err == nil {
		t.Fatal("writer can read raw journal")
	}
	if _, err := db.Exec(`SELECT * FROM public.listings`); err == nil {
		t.Fatal("writer can read raw listings")
	}
	if _, err := db.Exec(`SELECT public.check_listing_pointers()`); err == nil {
		t.Fatal("writer can invoke deferred guard directly")
	}
	handler := corrector.Handler()
	ready := func() int {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/ready", nil))
		return w.Code
	}
	if ready() != 503 {
		t.Fatal("writer ready without an effective reason catalog")
	}
	credential := token("ts_agent", staff.ListingsAudience, reviewer)
	hashFor := func(id string) string {
		t.Helper()
		var value string
		if err := root.QueryRow(`SELECT encode(payload_hash,'hex') FROM listing_revisions WHERE id=$1`, id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	body := fixtureCorrection()
	body.ExpectedVersion = "3"
	body.SHA256 = hashFor(currentRevision)
	send := func(target http.Handler, revision string, command correctionCommand, auth string) (int, string) {
		encoded, _ := json.Marshal(command)
		// Keep the path construction centralized for the concurrent callers too.
		req := httptest.NewRequest("POST", "/internal/listings/revisions/"+revision+"/decisions", strings.NewReader(string(encoded)))
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Authorization", "Bearer "+auth)
		w := httptest.NewRecorder()
		target.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	counts := func() string {
		t.Helper()
		var value string
		if err := root.QueryRow(`SELECT
 (SELECT count(*) FROM listing_review.decision_events)::text||':'||
 (SELECT count(*) FROM listing_review.outbox)::text||':'||
 (SELECT count(*) FROM audit.log WHERE action='listing.reviewed')::text`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	requireUnchanged := func() {
		t.Helper()
		var unchanged bool
		if err := root.QueryRow(`SELECT version=3 AND pending_revision_id=$1::uuid AND state='published' AND published_revision_id='55555555-5555-4555-8555-555555555555' FROM listings`, currentRevision).Scan(&unchanged); err != nil || !unchanged || counts() != "0:0:0" {
			t.Fatal("failed command leaked a mutation", err, counts())
		}
	}
	if status, _ := send(handler, currentRevision, body, credential); status != 503 {
		t.Fatal("missing reason catalog accepted", status)
	}
	requireUnchanged()
	exec(`BEGIN;
 INSERT INTO listing_review.reasons(catalog_version,code,action,message_key) VALUES
 ('fixture-reasons-1','incomplete_description','changes_requested','listingReasonIncompleteDescription'),
 ('fixture-reasons-1','incomplete_description','rejected','listingReasonIncompleteDescription');
 INSERT INTO listing_review.reason_catalogs VALUES('fixture-reasons-1','` + reviewer + `',now());
 INSERT INTO listing_review.reason_head VALUES(true,'fixture-reasons-1',1);
 COMMIT;`)
	if ready() != 200 {
		t.Fatal("reviewed catalog did not make corrector ready")
	}
	for _, statement := range []string{
		`INSERT INTO listing_review.reasons VALUES('fixture-reasons-1','new_reason','rejected','listingNewReason')`,
		`UPDATE listing_review.reasons SET message_key='changed'`,
		`UPDATE listing_review.reason_catalogs SET reviewed_at=now()`,
	} {
		if _, err := root.Exec(statement); err == nil {
			t.Fatal("sealed reason version was mutable")
		}
	}
	for _, change := range []struct {
		name string
		edit func(*correctionCommand)
		want int
	}{
		{"wrong hash", func(c *correctionCommand) { c.SHA256 = strings.Repeat("0", 64) }, 409},
		{"stale listing", func(c *correctionCommand) { c.ExpectedVersion = "2" }, 409},
		{"future listing", func(c *correctionCommand) { c.ExpectedVersion = "4" }, 409},
		{"stale reason catalog", func(c *correctionCommand) { c.ReasonCatalogVersion = "fixture-reasons-old" }, 409},
		{"unknown reason", func(c *correctionCommand) { c.ReasonCode = "unknown_reason" }, 400},
		{"approval", func(c *correctionCommand) { c.Decision = "approved" }, 400},
	} {
		command := body
		change.edit(&command)
		if status, _ := send(handler, currentRevision, command, credential); status != change.want {
			t.Fatal(change.name, status)
		}
		requireUnchanged()
	}
	if status, _ := send(handler, currentRevision, body, token("ts_agent", staff.ListingsAudience)); status != 403 {
		t.Fatal("self-review reached decision", status)
	}
	requireUnchanged()
	// Inject an actual audit failure AFTER the listing decision and outbox INSERT.
	// Any helper function must revoke PUBLIC execution or role isolation rightly
	// rejects the ingress before the intended failure point.
	exec(`CREATE TABLE public.listing_correction_fault(enabled boolean NOT NULL);
 INSERT INTO public.listing_correction_fault VALUES(true);
 CREATE FUNCTION public.listing_correction_fault() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
 BEGIN IF NEW.action='listing.reviewed' AND (SELECT enabled FROM public.listing_correction_fault) THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$;
 REVOKE ALL ON FUNCTION public.listing_correction_fault() FROM PUBLIC;
 CREATE TRIGGER listing_correction_fault BEFORE INSERT ON audit.log FOR EACH ROW EXECUTE FUNCTION public.listing_correction_fault();`)
	if status, _ := send(handler, currentRevision, body, credential); status != 503 {
		t.Fatal("audit failure not closed", status)
	}
	requireUnchanged()
	exec(`UPDATE public.listing_correction_fault SET enabled=false`)
	calls := 0
	corrector.owner.now = func() time.Time {
		calls++
		if calls == 1 {
			return time.Now()
		}
		return time.Now().Add(24 * time.Hour)
	}
	if status, result := send(handler, currentRevision, body, credential); status < 400 || calls != 2 || strings.Contains(result, "Private synthetic") {
		t.Fatal("expired session committed a correction", status, calls)
	}
	requireUnchanged()
	corrector.owner.now = time.Now
	status, result := send(handler, currentRevision, body, credential)
	if status != 200 || counts() != "1:1:1" {
		t.Fatal("valid correction failed", status, result, counts())
	}
	var preserved bool
	if err := root.QueryRow(`SELECT version=4 AND pending_revision_id IS NULL AND state='published' AND published_revision_id='55555555-5555-4555-8555-555555555555' FROM listings`).Scan(&preserved); err != nil || !preserved {
		t.Fatal("correction displaced previous public revision", err)
	}
	var privateLeak bool
	if err := root.QueryRow(`SELECT payload::text LIKE '%Private synthetic%' OR payload::text LIKE '%private-synthetic-signal%' FROM listing_review.outbox`).Scan(&privateLeak); err != nil || privateLeak {
		t.Fatal("outbox leaked review content", err)
	}
	// A replay returns the original result even after a later policy/head change.
	exec(`DELETE FROM listing_review.reason_head`)
	if ready() != 503 {
		t.Fatal("removed catalog still reported ready")
	}
	status, replay := send(handler, currentRevision, body, credential)
	if status != 200 || replay != result || counts() != "1:1:1" {
		t.Fatal("exact retry changed result or emitted twice", status, replay)
	}
	exec(`INSERT INTO listing_review.reason_head VALUES(true,'fixture-reasons-1',2)`)
	exec(`BEGIN;
 INSERT INTO listing_review.reasons VALUES('fixture-reasons-future','incomplete_description','rejected','listingReasonIncompleteDescription');
 INSERT INTO listing_review.reason_catalogs VALUES('fixture-reasons-future','` + reviewer + `',now()+interval '1 day');
 UPDATE listing_review.reason_head SET catalog_version='fixture-reasons-future',version=version+1;
 COMMIT;`)
	if ready() != 503 {
		t.Fatal("future-dated catalog reported ready")
	}
	if status, replayed := send(handler, currentRevision, body, credential); status != 200 || replayed != result {
		t.Fatal("historical retry depended on future policy", status)
	}
	futureAttempt := body
	futureAttempt.EventID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if status, _ := send(handler, currentRevision, futureAttempt, credential); status != 503 || counts() != "1:1:1" {
		t.Fatal("future-dated catalog accepted a command", status)
	}
	exec(`UPDATE listing_review.reason_head SET catalog_version='fixture-reasons-1',version=version+1`)
	different := body
	different.Decision = "rejected"
	if status, _ := send(handler, currentRevision, different, credential); status != 409 {
		t.Fatal("event id reused for different decision", status)
	}
	if status, _ := send(handler, currentRevision, body, token("ts_agent", staff.ListingsAudience, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")); status != 409 {
		t.Fatal("other human replayed decision", status)
	}
	different = body
	different.EventID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if status, _ := send(handler, currentRevision, different, credential); status != 409 {
		t.Fatal("decided revision accepted again", status)
	}
	if counts() != "1:1:1" {
		t.Fatal("conflicting replay emitted a new event")
	}
	// Two API instances race over one pending revision. Different event IDs must
	// yield one decision; identical retries must yield one decision and two ACKs.
	second, err := NewCorrector(context.Background(), db, access, fixtureID)
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 2; round++ {
		revision := fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012d", round+1)
		addPending(revision, round+3)
		command := body
		command.SHA256 = hashFor(revision)
		command.ExpectedVersion = fmt.Sprint(5 + 2*round)
		command.Decision = "rejected"
		command.EventID = fmt.Sprintf("cccccccc-cccc-4ccc-8ccc-%012d", round*2+1)
		commands := []correctionCommand{command, command}
		if round == 0 {
			commands[1].EventID = "cccccccc-cccc-4ccc-8ccc-000000000002"
			commands[1].Decision = "changes_requested"
		}
		outcomes := make(chan int, 2)
		var wg sync.WaitGroup
		for i, target := range []http.Handler{handler, second.Handler()} {
			wg.Add(1)
			go func(target http.Handler, c correctionCommand) {
				defer wg.Done()
				status, _ := send(target, revision, c, credential)
				outcomes <- status
			}(target, commands[i])
		}
		wg.Wait()
		close(outcomes)
		success, conflict := 0, 0
		for code := range outcomes {
			if code == 200 {
				success++
			} else if code == 409 {
				conflict++
			} else {
				t.Fatal("unexpected concurrent result", code)
			}
		}
		if (round == 0 && (success != 1 || conflict != 1)) || (round == 1 && success != 2) {
			t.Fatal("wrong concurrency result", success, conflict)
		}
		expected := fmt.Sprintf("%d:%d:%d", round+2, round+2, round+2)
		if counts() != expected {
			t.Fatal("concurrent duplicate side effects", counts(), expected)
		}
	}
	// Drift is checked on each command, not just construction.
	exec(`GRANT SELECT(nombre) ON public.usuario TO rac_listing_corrector_fixture`)
	if status, _ := send(handler, currentRevision, body, credential); status != 503 {
		t.Fatal("privilege drift accepted", status)
	}
	exec(`REVOKE SELECT(nombre) ON public.usuario FROM rac_listing_corrector_fixture`)
}
