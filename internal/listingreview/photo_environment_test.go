package listingreview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhotoPreviewEnvironmentIsSeparateAndOffByDefault(t *testing.T) {
	for _, flag := range []string{"", "false"} {
		t.Setenv("RAC_PHOTO_PREVIEW_ENABLED", flag)
		if store, err := photoPreviewFromEnvironment(); store != nil || err != nil {
			t.Fatal("preview implicitly enabled", err)
		}
	}
	t.Setenv("RAC_PHOTO_PREVIEW_ENABLED", "true")
	for _, env := range []string{"", "test", "qa", "prd"} {
		t.Setenv("RAC_ENV", env)
		if _, err := photoPreviewFromEnvironment(); err == nil {
			t.Fatal("preview enabled outside explicit DEV")
		}
	}
	t.Setenv("RAC_ENV", "dev")
	t.Setenv("RAC_PHOTO_STAGING_BUCKET", "private-staging")
	t.Setenv("RAC_PHOTO_QUARANTINE_BUCKET", "private-quarantine")
	t.Setenv("RAC_PHOTO_S3_ENDPOINT", "http://storage.example.test:9000")
	t.Setenv("RAC_PHOTO_S3_REGION", "us-east-1")
	file := func(name, value string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "synthetic-secret")
		if err := os.WriteFile(path, []byte(value+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(name+"_FILE", path)
	}
	file("RAC_PHOTO_PREVIEW_ACCESS_KEY", "synthetic-preview-only")
	file("RAC_PHOTO_PREVIEW_SECRET_KEY", "synthetic-private-preview-secret")
	if store, err := photoPreviewFromEnvironment(); store == nil || err != nil {
		t.Fatal("valid isolated preview rejected", err)
	}
	for name, value := range map[string]string{
		"RAC_PHOTO_PREVIEW_ENABLED": "yes", "PROFILE_S3_BUCKET": "private-staging",
		"RAC_PHOTO_QUARANTINE_BUCKET": "private-staging", "RAC_PHOTO_S3_ENDPOINT": "http://user:secret@storage.example.test",
		"PROFILE_S3_ACCESS_KEY": "synthetic-preview-only", "RAC_PHOTO_PREVIEW_SECRET_KEY_FILE": "missing-private-path",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, value)
			if _, err := photoPreviewFromEnvironment(); err == nil || strings.Contains(err.Error(), value) {
				t.Fatal("unsafe configuration accepted or leaked", err)
			}
		})
	}
	for _, name := range []string{"INGEST", "QUARANTINE", "STAGING"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key")
			if err := os.WriteFile(path, []byte("synthetic-preview-only"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("RAC_PHOTO_"+name+"_ACCESS_KEY_FILE", path)
			if _, err := photoPreviewFromEnvironment(); err == nil {
				t.Fatal("preview reused a pipeline credential")
			}
		})
	}
}
