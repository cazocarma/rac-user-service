package listingreview

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
)

func TestApprovalPostgresHTTP(t *testing.T) {
	dsn := os.Getenv("RAC_LISTING_APPROVAL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated approval database")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(u.Hostname(), "rac-migration-test-") || u.Path != "/listing_approver_http" {
		t.Fatal("refusing non-disposable approval database")
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
	const listing = "44444444-4444-4444-8444-444444444444"
	const owner = "22222222-2222-4222-8222-222222222222"
	exec(`CREATE ROLE rac_listing_approver_fixture LOGIN PASSWORD 'synthetic-approver-only-123456';
 GRANT USAGE ON SCHEMA listing_review,audit TO rac_listing_approver_fixture;
 GRANT EXECUTE ON FUNCTION ` + strings.Join(approvalSignatures, ",") + ` TO rac_listing_approver_fixture;
 INSERT INTO audit.chain_heads(chain_id) VALUES('88888888-8888-4888-8888-888888888888');
 INSERT INTO audit.writer_principals VALUES('rac_listing_approver_fixture','99999999-9999-4999-8999-999999999999','88888888-8888-4888-8888-888888888888');
 INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) VALUES('` + owner + `','Approval fixture','approval@example.test','compa','` + fixtureID + `');
 INSERT INTO compa_perfil(id,usuario_id,descripcion,tarifa_hora) VALUES('33333333-3333-4333-8333-333333333333','` + owner + `','Synthetic',12000);
 INSERT INTO listings(id,compa_id) VALUES('` + listing + `','33333333-3333-4333-8333-333333333333');`)
	// Superuser fixtures: payloads are synthetic and the catalog entry stays
	// proposed. Nothing here approves D04 categories or a real listing.
	number := 0
	addPending := func(id, payload string) {
		t.Helper()
		number++
		exec(fmt.Sprintf(`
 INSERT INTO listing_revisions(id,listing_id,revision_no,payload_canonical,assessment,risk_score,policy_version)
 VALUES('%s','%s',%d,'%s','{"signals":["private-synthetic-signal"]}',10,'fixture-1');
 UPDATE listings SET pending_revision_id='%s',version=version+1 WHERE id='%s';`, id, listing, number, payload, id, listing))
	}
	const candidate = `{"activities":[{"note":"","slug":"cine"}],"description":"Private synthetic candidate","photo_version":""}`
	u.User = url.UserPassword("rac_listing_approver_fixture", "synthetic-approver-only-123456")
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	access, token := readerAccess(t)
	var hookCalls atomic.Int32
	var hookFailure atomic.Pointer[error]
	fail := func(err error) {
		if err == nil {
			hookFailure.Store(nil)
		} else {
			hookFailure.Store(&err)
		}
	}
	hook := func(ctx context.Context, tx *sql.Tx, subject string) (listings.Checked, error) {
		hookCalls.Add(1)
		if subject != fixtureID {
			return listings.Checked{}, errors.New("unexpected owner subject")
		}
		// The owner transaction stays open until the approval commits.
		if _, err := tx.ExecContext(ctx, `SELECT 1 FROM usuario WHERE keycloak_id=$1 FOR KEY SHARE`, subject); err != nil {
			return listings.Checked{}, err
		}
		if failure := hookFailure.Load(); failure != nil {
			return listings.Checked{}, *failure
		}
		return listings.Checked{Documents: true, Identity: false}, nil
	}
	policy := ApprovalPolicy{ListingPolicy: "fixture-1", AllowProposedActivities: true}
	if _, err := NewApprover(context.Background(), db, root, access, fixtureID, ApprovalPolicy{ListingPolicy: "fixture 1"}, hook); err == nil {
		t.Fatal("invalid listing policy accepted")
	}
	if _, err := NewApprover(context.Background(), db, nil, access, fixtureID, policy, hook); err == nil {
		t.Fatal("approver without owner prerequisites accepted")
	}
	approver, err := NewApprover(context.Background(), db, root, access, fixtureID, policy, hook)
	if err != nil {
		t.Fatal("scoped approver rejected", err)
	}
	if _, err := New(context.Background(), db, access, fixtureID); err == nil {
		t.Fatal("approver accepted as reader")
	}
	if _, err := NewCorrector(context.Background(), db, access, fixtureID); err == nil {
		t.Fatal("approver accepted as corrector")
	}
	for _, statement := range []string{`SELECT * FROM public.listings`, `SELECT * FROM listing_review.decision_events`, `SELECT * FROM standing.account`} {
		if _, err := db.Exec(statement); err == nil {
			t.Fatal("approver read raw table", statement)
		}
	}
	handler := approver.Handler()
	credential := token("ts_agent", staff.ListingsAudience, reviewer)
	state := func(id string) (string, string) {
		t.Helper()
		var hash, version string
		if err := root.QueryRow(`SELECT encode(r.payload_hash,'hex'),l.version::text FROM listing_revisions r JOIN listings l ON l.id=r.listing_id WHERE r.id=$1`, id).Scan(&hash, &version); err != nil {
			t.Fatal(err)
		}
		return hash, version
	}
	command := func(event, revision string) approvalCommand {
		hash, version := state(revision)
		return approvalCommand{EventID: event, ExpectedVersion: version, SHA256: hash}
	}
	send := func(target http.Handler, revision string, c approvalCommand, auth string) (int, string) {
		encoded, _ := json.Marshal(c)
		req := httptest.NewRequest("POST", "/internal/listings/revisions/"+revision+"/approval", strings.NewReader(string(encoded)))
		req.Header.Set("Content-Type", "application/json")
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
 (SELECT count(*) FROM audit.log WHERE action='listing.reviewed')::text||':'||
 (SELECT count(*) FROM listing_revision_decisions)::text`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	unpublished := func(pending string) {
		t.Helper()
		var ok bool
		if err := root.QueryRow(`SELECT state='unpublished' AND published_revision_id IS NULL AND pending_revision_id=$1::uuid FROM listings`, pending).Scan(&ok); err != nil || !ok || counts() != "0:0:0:0" {
			t.Fatal("failed approval leaked a mutation", err, counts())
		}
	}
	expect := func(name, revision string, c approvalCommand, auth string, status int, code string) {
		t.Helper()
		got, body := send(handler, revision, c, auth)
		if got != status || (code != "" && !strings.Contains(body, `"`+code+`"`)) {
			t.Fatal(name, got, body)
		}
	}

	const photo = "aaaaaaaa-0000-4000-8000-000000000001"
	addPending(photo, `{"activities":[{"note":"","slug":"cine"}],"description":"Private synthetic candidate","photo_version":"photo-1"}`)
	expect("unapproved photo", photo, command("eeeeeeee-0000-4000-8000-000000000001", photo), credential, 409, "listing_photo_unapproved")
	unpublished(photo)

	const current = "aaaaaaaa-0000-4000-8000-000000000002"
	addPending(current, candidate)
	ok := command("eeeeeeee-0000-4000-8000-000000000002", current)
	for _, change := range []struct {
		name   string
		edit   func(*approvalCommand)
		status int
	}{
		{"wrong hash", func(c *approvalCommand) { c.SHA256 = strings.Repeat("0", 64) }, 409},
		{"stale listing", func(c *approvalCommand) { c.ExpectedVersion = "1" }, 409},
		{"bad version", func(c *approvalCommand) { c.ExpectedVersion = "01" }, 400},
		{"bad event", func(c *approvalCommand) { c.EventID = "not-an-id" }, 400},
	} {
		c := ok
		change.edit(&c)
		expect(change.name, current, c, credential, change.status, "")
		unpublished(current)
	}
	expect("self review", current, ok, token("ts_agent", staff.ListingsAudience), 403, "listing_self_review")
	expect("role without review", current, ok, token("support", staff.ListingsAudience, reviewer), 403, "")
	unpublished(current)

	strict, err := NewApprover(context.Background(), db, root, access, fixtureID, ApprovalPolicy{ListingPolicy: "fixture-1"}, hook)
	if err != nil {
		t.Fatal(err)
	}
	if status, body := send(strict.Handler(), current, ok, credential); status != 409 || !strings.Contains(body, "listing_activity_unavailable") {
		t.Fatal("proposed activity approved outside dev policy", status, body)
	}
	changed, err := NewApprover(context.Background(), db, root, access, fixtureID, ApprovalPolicy{ListingPolicy: "fixture-2", AllowProposedActivities: true}, hook)
	if err != nil {
		t.Fatal(err)
	}
	if status, body := send(changed.Handler(), current, ok, credential); status != 409 || !strings.Contains(body, "listing_policy_changed") {
		t.Fatal("submission approved under another policy", status, body)
	}
	unpublished(current)

	fail(fmt.Errorf("documents: %w", listings.ErrPrerequisites))
	expect("owner prerequisites", current, ok, credential, 409, "listing_owner_prerequisites_required")
	fail(errors.New("documents unavailable"))
	expect("prerequisites unavailable", current, ok, credential, 503, "")
	fail(nil)
	unpublished(current)

	exec(`INSERT INTO standing.restriction VALUES('` + owner + `','publish_listing',now()-interval '1 minute',NULL)`)
	expect("publish restriction", current, ok, credential, 409, "listing_owner_restricted")
	exec(`DELETE FROM standing.restriction; UPDATE standing.account SET status='suspended' WHERE subject_id='` + owner + `'`)
	expect("suspended owner", current, ok, credential, 409, "listing_owner_restricted")
	exec(`UPDATE standing.account SET status='active' WHERE subject_id='` + owner + `'`)
	exec(`UPDATE activity_categories SET status='retired' WHERE slug='cine'`)
	expect("retired activity", current, ok, credential, 409, "listing_activity_unavailable")
	exec(`UPDATE activity_categories SET status='active' WHERE slug='cine'`)
	unpublished(current)

	// Audit failure after the decision/outbox/pointer writes rolls all of them back.
	exec(`CREATE TABLE public.listing_approval_fault(enabled boolean NOT NULL);
 INSERT INTO public.listing_approval_fault VALUES(true);
 CREATE FUNCTION public.listing_approval_fault() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
 BEGIN IF NEW.action='listing.reviewed' AND (SELECT enabled FROM public.listing_approval_fault) THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$;
 REVOKE ALL ON FUNCTION public.listing_approval_fault() FROM PUBLIC;
 CREATE TRIGGER listing_approval_fault BEFORE INSERT ON audit.log FOR EACH ROW EXECUTE FUNCTION public.listing_approval_fault();`)
	expect("audit failure", current, ok, credential, 503, "")
	unpublished(current)
	exec(`UPDATE public.listing_approval_fault SET enabled=false`)

	calls := 0
	approver.owner.now = func() time.Time {
		calls++
		if calls == 1 {
			return time.Now()
		}
		return time.Now().Add(24 * time.Hour)
	}
	if status, body := send(handler, current, ok, credential); status < 400 || calls != 2 {
		t.Fatal("expired session committed an approval", status, body, calls)
	}
	unpublished(current)
	approver.owner.now = time.Now

	before := hookCalls.Load()
	status, result := send(handler, current, ok, credential)
	if status != 200 || counts() != "1:1:1:1" || hookCalls.Load() != before+1 {
		t.Fatal("valid approval failed", status, result, counts())
	}
	var published bool
	if err := root.QueryRow(`SELECT state='published' AND published_revision_id=$1::uuid AND pending_revision_id IS NULL FROM listings`, current).Scan(&published); err != nil || !published {
		t.Fatal("approval did not publish the reviewed revision", err)
	}
	var recorded string
	if err := root.QueryRow(`SELECT command->>'requirements' FROM listing_review.decision_events`).Scan(&recorded); err != nil ||
		recorded != `{"identity": false, "documents": true, "allow_proposed_activities": true}` {
		t.Fatal("decision did not record evaluated requirements", recorded, err)
	}
	var privateLeak bool
	if err := root.QueryRow(`SELECT payload::text LIKE '%Private synthetic%' OR payload::text LIKE '%private-synthetic-signal%' FROM listing_review.outbox`).Scan(&privateLeak); err != nil || privateLeak {
		t.Fatal("outbox leaked review content", err)
	}
	// Retries replay the recorded result without re-evaluating the owner.
	if status, replay := send(handler, current, ok, credential); status != 200 || replay != result || hookCalls.Load() != before+1 || counts() != "1:1:1:1" {
		t.Fatal("exact retry changed result or re-evaluated", status, replay)
	}
	expect("other human replay", current, ok, token("ts_agent", staff.ListingsAudience, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), 409, "")
	again := ok
	again.EventID = "eeeeeeee-0000-4000-8000-000000000003"
	expect("decided revision", current, again, credential, 409, "")
	if counts() != "1:1:1:1" {
		t.Fatal("conflicting retry emitted effects", counts())
	}

	// A new submission keeps the approved snapshot public until its own decision.
	second, err := NewApprover(context.Background(), db, root, access, fixtureID, policy, hook)
	if err != nil {
		t.Fatal(err)
	}
	approved := current
	for round := 0; round < 2; round++ {
		revision := fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012d", round+1)
		addPending(revision, candidate)
		var kept bool
		if err := root.QueryRow(`SELECT published_revision_id=$1::uuid FROM listings`, approved).Scan(&kept); err != nil || !kept {
			t.Fatal("new submission displaced the approved revision", err)
		}
		c := command(fmt.Sprintf("cccccccc-cccc-4ccc-8ccc-%012d", round*2+1), revision)
		commands := []approvalCommand{c, c}
		if round == 0 {
			commands[1].EventID = "cccccccc-cccc-4ccc-8ccc-000000000002"
		}
		outcomes := make(chan int, 2)
		var wg sync.WaitGroup
		for i, target := range []http.Handler{handler, second.Handler()} {
			wg.Add(1)
			go func(target http.Handler, c approvalCommand) {
				defer wg.Done()
				status, _ := send(target, revision, c, credential)
				outcomes <- status
			}(target, commands[i])
		}
		wg.Wait()
		close(outcomes)
		success, conflict := 0, 0
		for code := range outcomes {
			switch code {
			case 200:
				success++
			case 409:
				conflict++
			default:
				t.Fatal("unexpected concurrent result", code)
			}
		}
		if (round == 0 && (success != 1 || conflict != 1)) || (round == 1 && success != 2) {
			t.Fatal("wrong concurrency result", success, conflict)
		}
		if want := fmt.Sprintf("%d:%d:%d:%d", round+2, round+2, round+2, round+2); counts() != want {
			t.Fatal("concurrent duplicate side effects", counts(), want)
		}
		if err := root.QueryRow(`SELECT published_revision_id=$1::uuid FROM listings`, revision).Scan(&kept); err != nil || !kept {
			t.Fatal("concurrent approval did not publish", err)
		}
		approved = revision
	}
	exec(`GRANT SELECT(nombre) ON public.usuario TO rac_listing_approver_fixture`)
	if status, _ := send(handler, current, ok, credential); status != 503 {
		t.Fatal("privilege drift accepted", status)
	}
	exec(`REVOKE SELECT(nombre) ON public.usuario FROM rac_listing_approver_fixture`)
}
