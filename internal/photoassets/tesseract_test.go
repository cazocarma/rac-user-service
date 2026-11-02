package photoassets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cazocarma/rac-user-service/internal/photos"
)

func TestPhotoProcessingTesseract(t *testing.T) {
	if os.Getenv("RAC_TESSERACT_TEST") != "1" {
		t.Skip("requires isolated local Tesseract laboratory")
	}
	const binary = "/usr/bin/tesseract"
	const models = "/usr/share/tesseract-ocr/5/tessdata"
	ocr, err := NewTesseract(context.Background(), binary, models)
	if err != nil {
		t.Fatal("local OCR startup failed", err)
	}
	for _, tc := range []struct{ name, expected string }{{"contact_border", ContactCorrection}, {"benign", NeedsReview}} {
		t.Run(tc.name, func(t *testing.T) {
			upload := imageFixture(t, tc.name)
			processor, err := NewProcessor("fixture-pipeline-1", ocr, engineFixture(t))
			if err != nil {
				t.Fatal(err)
			}
			result, err := processor.Process(context.Background(), upload.Source(), readerFunc(func(context.Context, string) ([]byte, error) { return upload.Bytes(), nil }))
			if err != nil || result.Disposition() != tc.expected {
				t.Fatal("local OCR/normalizer/shared detector mismatch", result.Disposition(), err)
			}
		})
	}
	// Updating trained data after startup cannot be labelled with its old hash.
	temporary := t.TempDir()
	for _, language := range []string{"spa", "eng"} {
		if err := os.WriteFile(filepath.Join(temporary, language+".traineddata"), []byte("synthetic-model-placeholder"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	changed, err := NewTesseract(context.Background(), binary, temporary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(temporary, "spa.traineddata"), []byte("changed-model"), 0600); err != nil {
		t.Fatal(err)
	}
	normalized, err := photos.NormalizeFull(sourceFixture(t).Bytes(), "image/png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changed.Extract(context.Background(), normalized); !errors.Is(err, ErrProcessing) {
		t.Fatal("changed model attributed to old version", err)
	}
}

func TestOCRBoundedOutputDoesNotTruncateToSuccess(t *testing.T) {
	output := &boundedOutput{limit: 3}
	if _, err := output.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("d")); !errors.Is(err, ErrProcessing) || !output.overflow || output.String() != "abc" {
		t.Fatal("overflow silently truncated to success", err)
	}
	if _, err := NewTesseract(context.Background(), "relative-binary", "relative-models"); !errors.Is(err, ErrInvalid) {
		t.Fatal("relative executable/config accepted")
	}
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-private-secret")
	t.Setenv("TESSDATA_PREFIX", "/synthetic-untrusted-models")
	command := localCommand(context.Background(), "/usr/bin/tesseract", "--version")
	for _, value := range command.Env {
		if strings.HasPrefix(value, "AWS_") || strings.HasPrefix(value, "TESSDATA_PREFIX=") {
			t.Fatal("OCR inherited ambient secrets/config")
		}
	}
}
