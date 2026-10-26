package sessioncontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

type fakeIdentity struct {
	refs         []Ref
	live         map[Ref]bool
	loads, posts int
	loseACK      bool
	onLoad       func()
}

func (g *fakeIdentity) Check(context.Context) error { return nil }
func (g *fakeIdentity) Snapshot(context.Context, string) ([]Ref, error) {
	g.loads++
	if g.onLoad != nil {
		g.onLoad()
	}
	return append([]Ref{}, g.refs...), nil
}
func (g *fakeIdentity) Revoke(_ context.Context, _ string, refs []Ref) error {
	g.posts++
	for _, ref := range refs {
		delete(g.live, ref)
	}
	if g.loseACK {
		g.loseACK = false
		return ErrUnavailable
	}
	return nil
}

func TestStandingSessionsPostgres(t *testing.T) {
	dsn := os.Getenv("RAC_SESSION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated session-effects database")
	}
	u, err := url.Parse(dsn)
	if err != nil || os.Getenv("RAC_SESSION_TEST_ISOLATED") != "1" || u.Path != "/session_effects" || !strings.HasPrefix(u.Hostname(), "rac-migration-test-") {
		t.Fatal("isolated session-effects fixture required")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("fixture database unavailable")
	}
	defer admin.Close()
	exec := func(t testing.TB, query string, args ...any) {
		t.Helper()
		if _, err := admin.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	var chain, actor string
	if admin.QueryRow(`SELECT gen_random_uuid()::text,gen_random_uuid()::text`).Scan(&chain, &actor) != nil {
		t.Fatal("fixture IDs unavailable")
	}
	exec(t, `INSERT INTO audit.chain_heads(chain_id) VALUES($1)`, chain)
	exec(t, `INSERT INTO audit.writer_principals VALUES('postgres',$1,$2) ON CONFLICT DO NOTHING`, actor, chain)
	// The test authenticates as the actual low-privilege login, not a superuser
	// connection with SET ROLE that could later RESET ROLE to bypass grants.
	exec(t, `ALTER ROLE rac_standing_sessions LOGIN PASSWORD 'synthetic-session-role-only-123456'`)
	u.User = url.UserPassword("rac_standing_sessions", "synthetic-session-role-only-123456")
	q := u.Query()
	q.Del("options")
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal("scoped connection unavailable")
	}
	defer db.Close()
	db.SetMaxOpenConns(8)
	store := &Postgres{DB: db}
	ctx := context.Background()

	change := func(t testing.TB, subject, status string) {
		t.Helper()
		if _, err := admin.Exec(`SELECT standing.change_account(gen_random_uuid(),$1,(SELECT version FROM standing.account WHERE subject_id=$1),$2,'[]'::jsonb,gen_random_uuid())`, subject, status); err != nil {
			t.Fatal(err)
		}
	}
	setup := func(t *testing.T) string {
		t.Helper()
		var subject string
		if admin.QueryRow(`SELECT gen_random_uuid()::text`).Scan(&subject) != nil {
			t.Fatal("fixture identity unavailable")
		}
		exec(t, `INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) VALUES($1::uuid,'Synthetic',$1::text||'@fixture.test','cliente',$1::text)`, subject)
		change(t, subject, "suspended")
		t.Cleanup(func() { change(t, subject, "active") })
		return subject
	}
	identity := func(n int) *fakeIdentity {
		g := &fakeIdentity{refs: make([]Ref, 0, n), live: map[Ref]bool{}}
		for i := 0; i < n; i++ {
			ref := Ref{fmt.Sprintf("original-session-%03d~v2", i), i%2 == 1}
			g.refs = append(g.refs, ref)
			g.live[ref] = true
		}
		return g
	}
	step := func(t *testing.T, w *Worker) {
		t.Helper()
		worked, err := w.Step(ctx)
		if !worked || err != nil {
			t.Fatal("session step failed", err)
		}
	}

	t.Run("ack-loss-restart-and-bounded-batches", func(t *testing.T) {
		subject := setup(t)
		g := identity(70)
		g.loseACK = true
		w := &Worker{Store: store, Gateway: g}
		if _, err := w.Step(ctx); !errors.Is(err, ErrUnavailable) {
			t.Fatal("lost external ACK was not retried")
		}
		fresh := Ref{"new-protective-login", false}
		g.live[fresh] = true
		g.refs = append(g.refs, fresh)
		// Reconstruct the process-facing repository after a failed POST. Its
		// only capture must come from PostgreSQL, never this new remote list.
		w = &Worker{Store: &Postgres{DB: db}, Gateway: g}
		exec(t, `UPDATE standing.session_effect SET due_at=clock_timestamp() WHERE subject_id=$1`, subject)
		for i := 0; i < 3; i++ {
			step(t, w)
		}
		stats, err := store.Stats(ctx)
		if err != nil || stats.Pending != 0 || g.loads != 1 || len(g.live) != 1 || !g.live[fresh] {
			t.Fatal("retry recaptured or lost a new login", stats, g.loads)
		}
		var raw []byte
		var next int
		var state string
		if admin.QueryRow(`SELECT sessions,next_index,state FROM standing.session_effect WHERE subject_id=$1`, subject).Scan(&raw, &next, &state) != nil {
			t.Fatal("journal missing")
		}
		var original []Ref
		if json.Unmarshal(raw, &original) != nil || len(original) != 70 || next != 70 || state != "completed" {
			t.Fatal("journal was replaced or completed early")
		}
	})

	t.Run("reversal-before-save", func(t *testing.T) {
		subject := setup(t)
		g := identity(1)
		g.onLoad = func() { change(t, subject, "active") }
		step(t, &Worker{Store: store, Gateway: g})
		if g.posts != 0 || len(g.live) != 1 {
			t.Fatal("reversed sanction reached identity mutation")
		}
		var state string
		var empty bool
		if admin.QueryRow(`SELECT state,sessions IS NULL FROM standing.session_effect WHERE subject_id=$1`, subject).Scan(&state, &empty) != nil || state != "superseded" || !empty {
			t.Fatal("stale capture persisted")
		}
	})

	t.Run("reversal-after-save", func(t *testing.T) {
		subject := setup(t)
		g := identity(1)
		fresh := Ref{"new-after-reversal", false}
		wrapped := &captureHook{Store: store, after: func() { change(t, subject, "active"); g.live[fresh] = true }}
		step(t, &Worker{Store: wrapped, Gateway: g})
		if g.loads != 1 || len(g.live) != 1 || !g.live[fresh] {
			t.Fatal("post-reversal login was selected")
		}
	})

	t.Run("lease-expiry-concurrent-claims-and-null-fencing", func(t *testing.T) {
		subject := setup(t)
		var event string
		if admin.QueryRow(`SELECT event_id FROM standing.session_effect WHERE subject_id=$1`, subject).Scan(&event) != nil {
			t.Fatal("effect missing")
		}
		var applied bool
		if db.QueryRow(`SELECT standing.capture_sessions($1,NULL,'[]')`, event).Scan(&applied) != nil || applied {
			t.Fatal("null claim bypassed fencing")
		}
		var mu sync.Mutex
		var claimed []*Work
		var wg sync.WaitGroup
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w, e := store.Claim(ctx)
				if e != nil {
					t.Error(e)
				}
				if w != nil {
					mu.Lock()
					claimed = append(claimed, w)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if len(claimed) != 1 {
			t.Fatal("concurrent claim ownership", len(claimed))
		}
		old := claimed[0]
		exec(t, `UPDATE standing.session_effect SET claimed_until=clock_timestamp()-interval '1 second' WHERE event_id=$1`, old.Event)
		current, err := store.Claim(ctx)
		if err != nil || current == nil || current.Claim == old.Claim {
			t.Fatal("expired claim not replaced")
		}
		refs := []Ref{{"original~opaque", false}}
		if store.Capture(ctx, old, refs) != ErrClaimLost || store.Retry(ctx, old) != ErrClaimLost {
			t.Fatal("expired owner retained rights")
		}
		if store.Capture(ctx, current, refs) != nil || store.Capture(ctx, current, refs) != nil {
			t.Fatal("capture retry failed")
		}
		if store.Capture(ctx, current, []Ref{{"new-session", false}}) != ErrClaimLost {
			t.Fatal("saved capture replaced")
		}
		if store.Advance(ctx, old, 1) != ErrClaimLost || store.Advance(ctx, current, 1) != nil {
			t.Fatal("advance fencing failed")
		}
	})

	t.Run("authority-lock-race-and-lock-order", func(t *testing.T) {
		subject := setup(t)
		work, err := store.Claim(ctx)
		if err != nil || work == nil {
			t.Fatal("claim unavailable")
		}
		tx, err := admin.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err = tx.Exec(`SELECT 1 FROM standing.account WHERE subject_id=$1 FOR UPDATE`, subject); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			c, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			done <- store.Capture(c, work, []Ref{{"old", false}})
		}()
		deadline := time.Now().Add(3 * time.Second)
		for {
			var waiting bool
			if admin.QueryRow(`SELECT EXISTS(SELECT FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT standing.capture_sessions%')`).Scan(&waiting) != nil {
				t.Fatal("lock observation unavailable")
			}
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("capture never waited on authority")
			}
			time.Sleep(10 * time.Millisecond)
		}
		c, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		if _, err = tx.ExecContext(c, `SELECT standing.change_account(gen_random_uuid(),$1,(SELECT version FROM standing.account WHERE subject_id=$1),'active','[]',gen_random_uuid())`, subject); err != nil {
			t.Fatal("lock order deadlocked", err)
		}
		if tx.Commit() != nil {
			t.Fatal("reversal commit failed")
		}
		if <-done != ErrClaimLost {
			t.Fatal("stale capture survived committed reversal")
		}
	})

	t.Run("negative-permissions-and-invalid-captures", func(t *testing.T) {
		setup(t)
		work, err := store.Claim(ctx)
		if err != nil || work == nil {
			t.Fatal("claim missing")
		}
		for _, query := range []string{`SELECT * FROM standing.session_effect`, `SELECT * FROM standing.outbox`, `SELECT correo FROM usuario`, `SELECT * FROM audit.log`,
			`UPDATE standing.account SET status='active'`, `ALTER ROLE rac_standing_sessions SUPERUSER`, `SELECT standing.change_account(NULL,NULL,1,'active','[]',NULL)`} {
			if _, err := db.Exec(query); err == nil {
				t.Fatal("unexpected journal/authority privilege")
			}
		}
		for _, raw := range []string{`null`, `{}`, `[{"id":"old"}]`, `[{"id":"old","offline":false,"extra":true}]`, `[{"id":"old","offline":false},{"id":"old","offline":false}]`} {
			if db.QueryRow(`SELECT standing.capture_sessions($1,$2,$3::jsonb)`, work.Event, work.Claim, raw).Scan(new(bool)) == nil {
				t.Fatal("invalid capture accepted")
			}
		}
		if store.Capture(ctx, work, []Ref{}) != nil {
			t.Fatal("empty capture failed")
		}
		stats, err := store.Stats(ctx)
		if err != nil || stats.Pending != 0 {
			t.Fatal("empty capture left pending work")
		}
	})
}

type captureHook struct {
	Store
	after func()
}

func (s *captureHook) Capture(ctx context.Context, w *Work, refs []Ref) error {
	if err := s.Store.Capture(ctx, w, refs); err != nil {
		return err
	}
	s.after()
	return nil
}
