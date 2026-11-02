package photoassets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"image/jpeg"
	"math"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cazocarma/rac-platform/contentsignals"
)

type ocrFunc func(context.Context, []byte) (OCRResult, error)

func (f ocrFunc) Extract(ctx context.Context, raw []byte) (OCRResult, error) { return f(ctx, raw) }

type contentFunc func(context.Context, string) (contentsignals.Result, error)

func (f contentFunc) Analyze(ctx context.Context, text string) (contentsignals.Result, error) {
	return f(ctx, text)
}

func engineFixture(t *testing.T) contentsignals.Analyzer {
	t.Helper()
	engine, err := contentsignals.New(contentsignals.ProposedLexicon())
	if err != nil {
		t.Fatal(err)
	}
	return engine
}
func ocrFixture(text string) OCRResult {
	return OCRResult{Text: text, Version: "fixture-ocr-1", ModelSHA256: strings.Repeat("a", 64), ExecutableSHA256: strings.Repeat("b", 64)}
}
func imageFixture(t *testing.T, name string) Upload {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name + ".png")
	if err != nil {
		t.Fatal(err)
	}
	upload, err := Prepare(context.Background(), raw, "image/png", "fixture-pipeline-1")
	if err != nil {
		t.Fatal(err)
	}
	return upload
}

func TestPhotoProcessingPreservesFrameAndPrivateProof(t *testing.T) {
	upload := imageFixture(t, "contact_border")
	for _, tc := range []struct{ text, disposition string }{
		{"CONTACTO +56 9 1234 5678", ContactCorrection}, {"CINE Y MUSEOS", NeedsReview}, {"vendo tussi", NeedsReview}, {"", NeedsReview},
	} {
		calls := 0
		var retained []byte
		processor, err := NewProcessor("fixture-pipeline-1", ocrFunc(func(_ context.Context, raw []byte) (OCRResult, error) {
			config, err := jpeg.DecodeConfig(bytes.NewReader(raw))
			if err != nil || config.Width != 1200 || config.Height != 400 {
				t.Fatal("OCR received a cropped or invalid image", config, err)
			}
			if bytes.Contains(raw, []byte("RAC-SYNTHETIC-PRIVATE-METADATA")) {
				t.Fatal("original metadata reached OCR")
			}
			retained = raw
			return ocrFixture(tc.text), nil
		}), engineFixture(t))
		if err != nil {
			t.Fatal(err)
		}
		result, err := processor.Process(context.Background(), upload.Source(), readerFunc(func(context.Context, string) ([]byte, error) {
			calls++
			if calls > 1 {
				return []byte("changed second read"), nil
			}
			return upload.Bytes(), nil
		}))
		if err != nil || calls != 1 || result.Disposition() != tc.disposition {
			t.Fatal("wrong processing result", calls, result.Disposition(), err)
		}
		if result.Digest() != sha256.Sum256(result.Image()) {
			t.Fatal("normalized digest mismatch")
		}
		if tc.text != "" && bytes.Contains(result.Assessment(), []byte(tc.text)) {
			t.Fatal("OCR text persisted in proof")
		}
		var proof struct {
			Pending  []string              `json:"pending_checks"`
			Analysis contentsignals.Result `json:"analysis"`
		}
		if json.Unmarshal(result.Assessment(), &proof) != nil || !slices.Contains(proof.Pending, "human_review") || !slices.Contains(proof.Pending, "banned_image_similarity") || !slices.Contains(proof.Analysis.Unevaluated, "minors") {
			t.Fatal("unchecked categories or required review lost")
		}
		retained[0] ^= 0xff
		copy := result.Image()
		copy[0] ^= 0xff
		if result.Digest() != sha256.Sum256(result.Image()) {
			t.Fatal("adapter/caller changed frozen image")
		}
		proofCopy := result.Assessment()
		proofCopy[0] ^= 0xff
		if !json.Valid(result.Assessment()) {
			t.Fatal("caller changed private proof")
		}
	}
}

func TestPhotoProcessingFailsClosed(t *testing.T) {
	upload := sourceFixture(t)
	reader := readerFunc(func(context.Context, string) ([]byte, error) { return upload.Bytes(), nil })
	for _, tc := range []struct {
		name     string
		ocr      OCR
		analyzer contentsignals.Analyzer
	}{
		{"OCR unavailable", ocrFunc(func(context.Context, []byte) (OCRResult, error) {
			return OCRResult{}, errors.New("private provider diagnostic")
		}), engineFixture(t)},
		{"missing OCR metadata", ocrFunc(func(context.Context, []byte) (OCRResult, error) { return OCRResult{Text: "Cine"}, nil }), engineFixture(t)},
		{"invalid UTF8", ocrFunc(func(context.Context, []byte) (OCRResult, error) { return ocrFixture(string([]byte{255})), nil }), engineFixture(t)},
		{"oversized OCR", ocrFunc(func(context.Context, []byte) (OCRResult, error) {
			return ocrFixture(strings.Repeat("a", contentsignals.MaxInput+1)), nil
		}), engineFixture(t)},
		{"analyzer unavailable", ocrFunc(func(context.Context, []byte) (OCRResult, error) { return ocrFixture("cine"), nil }), contentFunc(func(context.Context, string) (contentsignals.Result, error) {
			return contentsignals.Result{}, errors.New("private rules diagnostic")
		})},
		{"invalid score", ocrFunc(func(context.Context, []byte) (OCRResult, error) { return ocrFixture("cine"), nil }), contentFunc(func(context.Context, string) (contentsignals.Result, error) {
			return contentsignals.Result{AnalyzerVersion: "fixture-1", PolicyVersion: "fixture-1", Signals: []contentsignals.Signal{{Category: "drugs", RuleID: "fixture.invalid", Score: math.NaN(), Spans: []contentsignals.Span{{Start: 0, End: 1}}}}}, nil
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			processor, err := NewProcessor("fixture-pipeline-1", tc.ocr, tc.analyzer)
			if err != nil {
				t.Fatal(err)
			}
			result, err := processor.Process(context.Background(), upload.Source(), reader)
			if !errors.Is(err, ErrProcessing) || len(result.Image()) != 0 || len(result.Assessment()) != 0 {
				t.Fatal("failure produced an apparently processed image", err)
			}
		})
	}
	processor, _ := NewProcessor("other-pipeline", ocrFunc(func(context.Context, []byte) (OCRResult, error) {
		t.Fatal("wrong pipeline reached OCR")
		return OCRResult{}, nil
	}), engineFixture(t))
	if _, err := processor.Process(context.Background(), upload.Source(), reader); !errors.Is(err, ErrPipelineVersion) {
		t.Fatal("wrong pipeline accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	processor, _ = NewProcessor("fixture-pipeline-1", ocrFunc(func(context.Context, []byte) (OCRResult, error) { cancel(); return ocrFixture("cine"), nil }), engineFixture(t))
	if _, err := processor.Process(ctx, upload.Source(), reader); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled analysis returned image", err)
	}
}
