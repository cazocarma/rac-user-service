package listingreview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhotoApprovalEnvironmentIsExplicitSeparateAndDevOnly(t *testing.T) {
	approval := ApprovalPolicy{ListingPolicy: "fixture-1"}
	for _, flag := range []string{"", "false"} {
		t.Setenv("RAC_PHOTO_PROMOTION_ENABLED", flag)
		if cfg, err := photoApprovalEnvironment(approval); cfg != nil || err != nil {
			t.Fatal("implicit promotion activation", err)
		}
	}
	t.Setenv("RAC_PHOTO_PROMOTION_ENABLED", "true")
	for _, env := range []string{"", "qa", "prd", "test"} {
		t.Setenv("RAC_ENV", env)
		if _, err := photoApprovalEnvironment(approval); err == nil {
			t.Fatal("promotion accepted outside explicit DEV")
		}
	}
	t.Setenv("RAC_ENV", "dev")
	t.Setenv("RAC_PHOTO_PREVIEW_ENABLED", "true")
	t.Setenv("RAC_PHOTO_S3_ENDPOINT", "http://storage.example.test:9000/")
	t.Setenv("RAC_PHOTO_S3_REGION", "us-east-1")
	t.Setenv("RAC_PHOTO_STAGING_BUCKET", "synthetic-staging")
	t.Setenv("RAC_PHOTO_QUARANTINE_BUCKET", "synthetic-quarantine")
	t.Setenv("RAC_PHOTO_MEDIA_BUCKET", "synthetic-approved-media")
	t.Setenv("RAC_PHOTO_PIPELINE_VERSION", "synthetic-pipeline-1")
	t.Setenv("RAC_PHOTO_MEDIA_TARGET_ID", "11111111-1111-4111-8111-111111111111")
	t.Setenv("LISTING_REVIEW_PHOTO_APPROVER_DATABASE_URL", "postgres://synthetic-photo:synthetic-pass@postgres/synthetic?sslmode=disable")
	file := func(name, value string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(path, []byte(value+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(name+"_FILE", path)
	}
	file("RAC_PHOTO_PREVIEW_ACCESS_KEY", "synthetic-preview")
	file("RAC_PHOTO_PREVIEW_SECRET_KEY", "synthetic-preview-password")
	file("RAC_PHOTO_PROMOTER_ACCESS_KEY", "synthetic-promoter")
	file("RAC_PHOTO_PROMOTER_SECRET_KEY", "synthetic-promoter-password")
	if cfg, err := photoApprovalEnvironment(approval); err != nil || cfg == nil || cfg.policy.Bucket != "synthetic-approved-media" || cfg.source == nil || cfg.destination == nil {
		t.Fatal("valid independent config rejected", err)
	}
	for name, value := range map[string]string{
		"RAC_PHOTO_PROMOTION_ENABLED": "yes", "RAC_PHOTO_PREVIEW_ENABLED": "false", "LISTING_REVIEW_PHOTO_APPROVER_DATABASE_URL": "",
		"RAC_PHOTO_MEDIA_BUCKET": "synthetic-staging", "RAC_PHOTO_QUARANTINE_BUCKET": "synthetic-staging",
		"PROFILE_S3_BUCKET": "synthetic-approved-media", "RAC_PHOTO_MEDIA_TARGET_ID": "private-target-not-a-uuid", "RAC_PHOTO_PIPELINE_VERSION": "invalid pipeline",
		"RAC_PHOTO_S3_ENDPOINT": "http://private:credential@storage.example.test:9000", "RAC_PHOTO_PROMOTER_SECRET_KEY_FILE": "missing-synthetic-file",
		"PROFILE_S3_ACCESS_KEY": "synthetic-promoter", "AWS_SECRET_ACCESS_KEY": "synthetic-promoter-password",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, value)
			if _, err := photoApprovalEnvironment(approval); err == nil || (value != "" && strings.Contains(err.Error(), value)) {
				t.Fatal("unsafe promotion config accepted or leaked", err)
			}
		})
	}
	for _, name := range []string{"LISTING_REVIEW_READER_DATABASE_URL", "LISTING_REVIEW_CORRECTOR_DATABASE_URL", "LISTING_REVIEW_APPROVER_DATABASE_URL"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, os.Getenv("LISTING_REVIEW_PHOTO_APPROVER_DATABASE_URL"))
			if _, err := photoApprovalEnvironment(approval); err == nil {
				t.Fatal("shared DB connection accepted")
			}
		})
	}
	for _, identity := range []string{"PREVIEW", "STAGING", "INGEST", "QUARANTINE"} {
		t.Run(identity, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, []byte("synthetic-promoter"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("RAC_PHOTO_"+identity+"_ACCESS_KEY_FILE", path)
			if _, err := photoApprovalEnvironment(approval); err == nil {
				t.Fatal("shared storage identity accepted")
			}
		})
	}
}
