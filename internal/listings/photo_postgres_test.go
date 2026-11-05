package listings

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cazocarma/rac-platform/contentsignals"
	"github.com/cazocarma/rac-user-service/internal/photoassets"
	"github.com/cazocarma/rac-user-service/internal/photostore"
)

type listingPhotoOCR string

func (o listingPhotoOCR) Extract(context.Context, []byte) (photoassets.OCRResult, error) {
	return photoassets.OCRResult{Text: string(o), Version: "synthetic-ocr-1", ModelSHA256: strings.Repeat("a", 64), ExecutableSHA256: strings.Repeat("b", 64)}, nil
}

type listingPhotoObjects map[string][]byte

func (m listingPhotoObjects) Put(_ context.Context, key string, raw []byte) error {
	if _, ok := m[key]; ok {
		return photostore.ErrExists
	}
	m[key] = slices.Clone(raw)
	return nil
}
func (m listingPhotoObjects) Get(_ context.Context, key string) ([]byte, error) {
	raw, ok := m[key]
	if !ok {
		return nil, photostore.ErrNotFound
	}
	return slices.Clone(raw), nil
}

func TestListingPhotoReferencePostgres(t *testing.T) {
	dsn := os.Getenv("RAC_LISTING_PHOTO_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable listing photo database")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Path != "/listing_photos" || !strings.HasPrefix(u.Hostname(), "rac-migration-test-") {
		t.Fatal("refusing non-disposable listing photo database")
	}
	root, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	q := u.Query()
	q.Set("options", "-c role=rac_user")
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(s string, args ...any) {
		t.Helper()
		if _, err := root.Exec(s, args...); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	owner := func() (string, string) {
		t.Helper()
		var subject, profile string
		if err := db.QueryRow(`INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) SELECT id,'Listing photo',id::text||'@example.test','compa',id::text FROM (SELECT gen_random_uuid() id) f RETURNING keycloak_id`).Scan(&subject); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`INSERT INTO compa_perfil(id,usuario_id,descripcion,tarifa_hora) SELECT gen_random_uuid(),id,'Photo fixture',12000 FROM usuario WHERE keycloak_id=$1 RETURNING id::text`, subject).Scan(&profile); err != nil {
			t.Fatal(err)
		}
		return subject, profile
	}
	subject, profile := owner()
	foreign, _ := owner()
	const pipeline = "listing-photo-fixture-1"
	release := photoassets.Release{Pipeline: pipeline, Commit: strings.Repeat("c", 40), ImageDigest: "sha256:" + strings.Repeat("d", 64)}
	exec(`INSERT INTO photo.processing_policies VALUES($1,60,0,3)`, pipeline)
	exec(`INSERT INTO photo.processing_releases VALUES($1,$2,$3)`, pipeline, release.Commit, release.ImageDigest)
	exec(`CREATE ROLE rac_listing_photo_worker_fixture LOGIN PASSWORD 'synthetic-listing-photo-worker';
 GRANT USAGE ON SCHEMA photo TO rac_listing_photo_worker_fixture;
 GRANT EXECUTE ON FUNCTION photo.claim_processing(text,text,text),photo.complete_processing(uuid,uuid,text,text,text,text,bytea,int,jsonb,text,int) TO rac_listing_photo_worker_fixture;`)
	workerURL, _ := url.Parse(dsn)
	workerURL.User = url.UserPassword("rac_listing_photo_worker_fixture", "synthetic-listing-photo-worker")
	workerDB, err := sql.Open("postgres", workerURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer workerDB.Close()
	queue, err := photoassets.NewPostgresQueue(ctx, workerDB)
	if err != nil {
		t.Fatal(err)
	}
	analyzer, err := contentsignals.New(contentsignals.ProposedLexicon())
	if err != nil {
		t.Fatal(err)
	}
	objects := listingPhotoObjects{}
	source := func(actor, text string, confirmed, processed bool) photoassets.Source {
		t.Helper()
		var buffer bytes.Buffer
		if err := png.Encode(&buffer, image.NewRGBA(image.Rect(0, 0, 64, 48))); err != nil {
			t.Fatal(err)
		}
		upload, err := photoassets.Prepare(ctx, buffer.Bytes(), "image/png", pipeline)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		src, err := photoassets.Reserve(ctx, tx, actor, upload)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		objects[src.ObjectKey()] = upload.Bytes()
		if confirmed {
			verified, err := photoassets.Verify(ctx, objects, src)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err := photoassets.Confirm(ctx, tx, actor, verified); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		if processed {
			processor, err := photoassets.NewProcessor(pipeline, listingPhotoOCR(text), analyzer)
			if err != nil {
				t.Fatal(err)
			}
			worker, err := photoassets.NewWorker(queue, objects, objects, processor, release)
			if err != nil {
				t.Fatal(err)
			}
			if claimed, err := worker.RunOnce(ctx); !claimed || err != nil {
				t.Fatal("photo preparation failed", err)
			}
		}
		return src
	}
	plain := source(subject, "Cine", true, true)
	suspicious := source(subject, "vendo tussi", true, true)
	contact := source(subject, "CONTACTO +56 9 1234 5678", true, true)
	foreignPhoto := source(foreign, "Cine", true, true)
	pending := source(subject, "", true, false)
	unconfirmed := source(subject, "", false, false)
	ready := func(actor, id, version string) bool {
		t.Helper()
		var value bool
		if err := db.QueryRow(`SELECT photo.owner_ready_reference($1,$2,$3)`, actor, id, version).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if !ready(subject, plain.ID(), pipeline) || ready(foreign, plain.ID(), pipeline) || ready(subject, plain.ID(), "other-pipeline") || ready(subject, contact.ID(), pipeline) {
		t.Fatal("owner/pipeline/contact reference check failed")
	}
	submit := func(id string, version int64, commit bool) (Receipt, error) {
		t.Helper()
		draft := fixtureDraft()
		draft.PhotoVersion = id
		prepared, err := preparer(t).Prepare(ctx, draft)
		if err != nil {
			return Receipt{}, err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		receipt, err := Submit(ctx, tx, subject, profile, version, prepared)
		if err != nil {
			return Receipt{}, err
		}
		if commit {
			err = tx.Commit()
		}
		return receipt, err
	}
	first, err := submit(plain.ID(), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	var bound, digest, payloadPhoto string
	if err := root.QueryRow(`SELECT l.asset_id::text,encode(l.normalized_sha256,'hex'),r.payload->>'photo_version' FROM photo.listing_references l JOIN listing_revisions r ON r.id=l.revision_id WHERE l.revision_id=$1`, first.RevisionID).Scan(&bound, &digest, &payloadPhoto); err != nil || bound != plain.ID() || payloadPhoto != plain.ID() || len(digest) != 64 {
		t.Fatal("photo not frozen with its exact revision", err)
	}
	rollback, err := submit(suspicious.ID(), 1, false)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := root.QueryRow(`SELECT count(*) FROM photo.listing_references WHERE revision_id=$1`, rollback.RevisionID).Scan(&count); err != nil || count != 0 {
		t.Fatal("rollback retained photo link", err)
	}
	second, err := submit(suspicious.ID(), 1, true)
	if err != nil {
		t.Fatal(err)
	}
	var listingRisk, photoRisk int
	var assessment []byte
	if err := root.QueryRow(`SELECT r.risk_score,p.risk_score,r.assessment FROM listing_revisions r JOIN photo.listing_references l ON l.revision_id=r.id JOIN photo.processing_results p ON p.asset_id=l.asset_id WHERE r.id=$1`, second.RevisionID).Scan(&listingRisk, &photoRisk, &assessment); err != nil || photoRisk == 0 || listingRisk < photoRisk {
		t.Fatal("photo risk did not participate in triage", err, listingRisk, photoRisk)
	}
	var proof map[string]any
	if json.Unmarshal(assessment, &proof) != nil || proof["photo"] == nil {
		t.Fatal("private proof reference absent")
	}
	for _, id := range []string{foreignPhoto.ID(), contact.ID(), pending.ID(), unconfirmed.ID(), "photo-1", "00000000-0000-4000-8000-000000000001"} {
		if _, err := submit(id, 2, true); !errors.Is(err, ErrPhotoUnavailable) {
			t.Fatal("unavailable/foreign source attached", id, err)
		}
	}
	var unchanged bool
	if err := root.QueryRow(`SELECT version=2 AND state='unpublished' AND published_revision_id IS NULL AND pending_revision_id=$2::uuid FROM listings WHERE id=$1`, first.ListingID, second.RevisionID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("failed attachment changed listing or published it", err)
	}
	for _, statement := range []string{"SELECT * FROM photo.listing_references", "SELECT * FROM photo.ready_listing_sources", "INSERT INTO photo.listing_references(revision_id) VALUES(gen_random_uuid())", "UPDATE photo.listing_references SET asset_id=asset_id", "DELETE FROM photo.listing_references"} {
		if _, err := db.Exec(statement); err == nil {
			t.Fatal("customer role gained private reference authority", statement)
		}
	}
	for _, statement := range []string{"UPDATE photo.listing_references SET asset_id=asset_id", "DELETE FROM photo.listing_references"} {
		if _, err := root.Exec(statement); err == nil {
			t.Fatal("reference history was mutated", statement)
		}
	}
}
