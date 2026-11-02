package listings

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestListingSubmitPostgres(t *testing.T) {
	dsn := os.Getenv("RAC_LISTING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated listing database")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid disposable database configuration")
	}
	query := u.Query()
	query.Set("options", "-c role=rac_user")
	u.RawQuery = query.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal("database open failed")
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var subject, profile string
	err = db.QueryRowContext(ctx, `INSERT INTO public.usuario(id,nombre,correo,rol,keycloak_id)
 SELECT id,'Fixture','listing-'||id::text||'@example.test','compa',id::text FROM (SELECT gen_random_uuid() AS id) fixture RETURNING keycloak_id`).Scan(&subject)
	if err != nil {
		t.Fatal("owner could not create fixture", err)
	}
	err = db.QueryRowContext(ctx, `INSERT INTO public.compa_perfil(id,usuario_id,descripcion,tarifa_hora) SELECT gen_random_uuid(),id,'Synthetic listing fixture',12000 FROM public.usuario WHERE keycloak_id=$1 RETURNING id::text`, subject).Scan(&profile)
	if err != nil {
		t.Fatal("profile fixture failed", err)
	}
	d := fixtureDraft()
	d.DisplayName = "Cris Á"
	submission, err := preparer(t).Prepare(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Submit(ctx, tx, subject, profile, 0, submission)
	if err != nil {
		tx.Rollback()
		t.Fatal("first submission failed", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if first.RevisionNo != 1 || first.Version != 1 || first.PayloadHash != submission.Hash() {
		t.Fatal("bad receipt")
	}
	var hash string
	if err = db.QueryRowContext(ctx, `SELECT encode(payload_hash,'hex') FROM public.listing_revisions WHERE id=$1`, first.RevisionID).Scan(&hash); err != nil || hash != hex.EncodeToString(first.PayloadHash[:]) {
		t.Fatal("UTF-8 hash changed in storage", err)
	}
	var pendingOnly bool
	if err = db.QueryRowContext(ctx, `SELECT state='unpublished' AND published_revision_id IS NULL AND pending_revision_id=$2::uuid FROM public.listings WHERE id=$1`, first.ListingID, first.RevisionID).Scan(&pendingOnly); err != nil || !pendingOnly {
		t.Fatal("submission became public", err)
	}

	// Cross-owner writes neither reveal nor alter the pending revision.
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Submit(ctx, tx, "foreign-fixture", profile, 1, submission)
	tx.Rollback()
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign owner was allowed", err)
	}

	// Caller rollback discards both the snapshot and its pointer/version.
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Submit(ctx, tx, subject, profile, 1, submission); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var count, version int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.listing_revisions WHERE listing_id=$1`, first.ListingID).Scan(&count); err != nil || count != 1 {
		t.Fatal("rollback retained a revision", err, count)
	}

	// Two instances submitting against one version: exactly one wins. The
	// loser must report a conflict, not persist a duplicate or overwrite it.
	start := make(chan struct{})
	outcomes := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				outcomes <- err
				return
			}
			defer tx.Rollback()
			_, err = Submit(ctx, tx, subject, profile, 1, submission)
			if err == nil {
				err = tx.Commit()
			}
			outcomes <- err
		}()
	}
	close(start)
	wins, conflicts := 0, 0
	for i := 0; i < 2; i++ {
		err := <-outcomes
		if err == nil {
			wins++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal("unexpected concurrent outcome", err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("lost update protection failed", wins, conflicts)
	}
	if err = db.QueryRowContext(ctx, `SELECT version FROM public.listings WHERE id=$1`, first.ListingID).Scan(&version); err != nil || version != 2 {
		t.Fatal("wrong committed version", err, version)
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.listing_revisions WHERE listing_id=$1`, first.ListingID).Scan(&count); err != nil || count != 2 {
		t.Fatal("concurrent revision loss/duplication", err, count)
	}
}
