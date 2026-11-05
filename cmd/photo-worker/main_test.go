package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkerSecretFilesAreBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	t.Setenv("TEST_PHOTO_SECRET_FILE", path)
	for _, tc := range []struct {
		raw, want string
		valid     bool
	}{
		{"synthetic-password\r\n", "synthetic-password", true},
		{"\r\n", "", false},
		{strings.Repeat("x", 8193), "", false},
	} {
		if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := secret("TEST_PHOTO_SECRET")
		if (err == nil) != tc.valid || (tc.valid && got != tc.want) {
			t.Fatal("secret file bounds/newline handling failed")
		}
	}
}

func TestWorkerCannotStartOutsideDev(t *testing.T) {
	for _, env := range []string{"", "qa", "prd", "production"} {
		t.Setenv("RAC_ENV", env)
		worker, db, err := prepare(context.Background())
		if err == nil || worker != nil || db != nil || err.Error() != "worker is restricted to dev" {
			t.Fatal("non-dev worker startup accepted")
		}
	}
}
