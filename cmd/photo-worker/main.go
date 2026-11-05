// photo-worker is an opt-in DEV process. Provision its function-only database
// login, release registration and two private IAM identities before starting.
package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cazocarma/rac-platform/contentsignals"
	"github.com/cazocarma/rac-user-service/internal/photoassets"
	"github.com/cazocarma/rac-user-service/internal/photostore"
	"github.com/cazocarma/rac-user-service/internal/secretfile"
)

func secret(name string) (string, error) {
	return secretfile.ReadEnvironment(name)
}

func prepare(ctx context.Context) (*photoassets.Worker, *sql.DB, error) {
	if os.Getenv("RAC_ENV") != "dev" {
		return nil, nil, errors.New("worker is restricted to dev")
	}
	dsn, err := secret("RAC_PHOTO_QUEUE_DATABASE_URL")
	if err != nil {
		return nil, nil, err
	}
	readAccess, err := secret("RAC_PHOTO_QUARANTINE_ACCESS_KEY")
	if err != nil {
		return nil, nil, err
	}
	readSecret, err := secret("RAC_PHOTO_QUARANTINE_SECRET_KEY")
	if err != nil {
		return nil, nil, err
	}
	writeAccess, err := secret("RAC_PHOTO_STAGING_ACCESS_KEY")
	if err != nil {
		return nil, nil, err
	}
	writeSecret, err := secret("RAC_PHOTO_STAGING_SECRET_KEY")
	if err != nil {
		return nil, nil, err
	}
	quarantineBucket, stagingBucket := os.Getenv("RAC_PHOTO_QUARANTINE_BUCKET"), os.Getenv("RAC_PHOTO_STAGING_BUCKET")
	if quarantineBucket == "" || stagingBucket == "" || quarantineBucket == stagingBucket || readAccess == writeAccess {
		return nil, nil, errors.New("separate buckets and identities required")
	}
	source, err := photostore.NewQuarantineS3(os.Getenv("RAC_PHOTO_S3_ENDPOINT"), os.Getenv("RAC_PHOTO_S3_REGION"), quarantineBucket, readAccess, readSecret)
	if err != nil {
		return nil, nil, err
	}
	staging, err := photostore.NewS3(os.Getenv("RAC_PHOTO_S3_ENDPOINT"), os.Getenv("RAC_PHOTO_S3_REGION"), stagingBucket, writeAccess, writeSecret)
	if err != nil {
		return nil, nil, err
	}
	ocr, err := photoassets.NewTesseract(ctx, os.Getenv("RAC_PHOTO_OCR_BINARY"), os.Getenv("RAC_PHOTO_OCR_DATA_DIR"))
	if err != nil {
		return nil, nil, err
	}
	analyzer, err := contentsignals.New(contentsignals.ProposedLexicon())
	if err != nil {
		return nil, nil, err
	}
	release := photoassets.Release{Pipeline: os.Getenv("RAC_PHOTO_PIPELINE_VERSION"), Commit: os.Getenv("RAC_PHOTO_BUILD_COMMIT"), ImageDigest: os.Getenv("RAC_PHOTO_IMAGE_DIGEST")}
	processor, err := photoassets.NewProcessor(release.Pipeline, ocr, analyzer)
	if err != nil {
		return nil, nil, err
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	queue, err := photoassets.NewPostgresQueue(ctx, db)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	worker, err := photoassets.NewWorker(queue, source, staging, processor, release)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	return worker, db, nil
}

func run(ctx context.Context) error {
	startup, cancel := context.WithTimeout(ctx, 20*time.Second)
	worker, db, err := prepare(startup)
	cancel()
	if err != nil {
		return errors.New("photo worker configuration unavailable")
	}
	defer db.Close()
	log.Print("photo worker started: private processing only; human review required")
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 90*time.Second)
		claimed, err := worker.RunOnce(attempt)
		cancel()
		delay := time.Second
		if err != nil && ctx.Err() == nil {
			// Do not print driver/OCR errors, source IDs, keys, assessments or contents.
			log.Print("photo processing attempt not acknowledged; queue retry policy applies")
			delay = 5 * time.Second
		} else if claimed && err == nil {
			log.Print("private photo processing result committed; human review pending")
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		log.Print("photo worker startup refused; check isolated configuration")
		os.Exit(1)
	}
}
