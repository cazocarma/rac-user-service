package listingreview

import (
	"errors"
	"os"

	"github.com/cazocarma/rac-user-service/internal/photostore"
	"github.com/cazocarma/rac-user-service/internal/secretfile"
)

// Explicit DEV-only opt-in. Never uses profile/ingest/worker credentials or a
// public URL, and never falls back to plaintext secrets in the environment.
func photoPreviewFromEnvironment() (PreviewStore, error) {
	fail := errors.New("invalid private photo preview configuration")
	switch os.Getenv("RAC_PHOTO_PREVIEW_ENABLED") {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, fail
	}
	if os.Getenv("RAC_ENV") != "dev" {
		return nil, fail
	}
	bucket := os.Getenv("RAC_PHOTO_STAGING_BUCKET")
	quarantine := os.Getenv("RAC_PHOTO_QUARANTINE_BUCKET")
	if bucket == "" || quarantine == "" || bucket == quarantine || bucket == os.Getenv("PROFILE_S3_BUCKET") {
		return nil, fail
	}
	access, err := secretfile.ReadEnvironment("RAC_PHOTO_PREVIEW_ACCESS_KEY")
	if err != nil {
		return nil, fail
	}
	secret, err := secretfile.ReadEnvironment("RAC_PHOTO_PREVIEW_SECRET_KEY")
	if err != nil {
		return nil, fail
	}
	if access == os.Getenv("PROFILE_S3_ACCESS_KEY") {
		return nil, fail
	}
	for _, name := range []string{"INGEST", "QUARANTINE", "STAGING"} {
		key := "RAC_PHOTO_" + name + "_ACCESS_KEY"
		if os.Getenv(key+"_FILE") != "" {
			other, err := secretfile.ReadEnvironment(key)
			if err != nil || access == other {
				return nil, fail
			}
		}
	}
	store, err := photostore.NewS3Reader(os.Getenv("RAC_PHOTO_S3_ENDPOINT"), os.Getenv("RAC_PHOTO_S3_REGION"), bucket, access, secret)
	if err != nil {
		return nil, fail
	}
	return store, nil
}
