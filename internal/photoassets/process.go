package photoassets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image/jpeg"
	"math"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cazocarma/rac-platform/contentsignals"
	"github.com/cazocarma/rac-user-service/internal/contentproof"
	"github.com/cazocarma/rac-user-service/internal/photos"
)

const FullNormalizerVersion = "photo-full-jpeg/1"
const NeedsReview = "needs_review"
const ContactCorrection = "contact_correction_required"

var ErrProcessing = errors.New("photo_processing_unavailable")
var ErrPipelineVersion = errors.New("photo_pipeline_version_mismatch")

type OCRResult struct{ Text, Version, ModelSHA256, ExecutableSHA256 string }
type OCR interface {
	Extract(context.Context, []byte) (OCRResult, error)
}

type Processor struct {
	version  string
	ocr      OCR
	analyzer contentsignals.Analyzer
}

func NewProcessor(version string, ocr OCR, analyzer contentsignals.Analyzer) (*Processor, error) {
	if !versionPattern.MatchString(version) || ocr == nil || analyzer == nil {
		return nil, ErrInvalid
	}
	return &Processor{version: version, ocr: ocr, analyzer: analyzer}, nil
}

type Processed struct {
	image, assessment []byte
	digest            [32]byte
	disposition       string
	risk              int
}

func (p Processed) Image() []byte { return slices.Clone(p.image) }

// Assessment is private T&S material: rule IDs/spans must never be returned in
// the public upload error or logged. OCR text is deliberately absent.
func (p Processed) Assessment() json.RawMessage { return slices.Clone(p.assessment) }
func (p Processed) Digest() [32]byte            { return p.digest }
func (p Processed) Disposition() string         { return p.disposition }
func (p Processed) RiskScore() int              { return p.risk }

func (p *Processor) Process(ctx context.Context, source Source, reader Reader) (Processed, error) {
	if source.pipeline != p.version {
		return Processed{}, ErrPipelineVersion
	}
	// Capture and verify one read; fetching again after checking its hash would
	// introduce a TOCTOU window between validation and decoding.
	raw, err := readVerified(ctx, reader, source)
	if err != nil {
		return Processed{}, err
	}
	normalized, err := photos.NormalizeFull(raw, source.media)
	if err != nil {
		return Processed{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Processed{}, err
	}
	recognized, err := p.ocr.Extract(ctx, slices.Clone(normalized))
	if err := ctx.Err(); err != nil {
		return Processed{}, err
	}
	if err != nil || !utf8.ValidString(recognized.Text) || len(recognized.Text) > contentsignals.MaxInput || !ocrLabel(recognized.Version) || len(recognized.ModelSHA256) != 64 {
		return Processed{}, ErrProcessing
	}
	if _, err := hex.DecodeString(recognized.ModelSHA256); err != nil {
		return Processed{}, ErrProcessing
	}
	if len(recognized.ExecutableSHA256) != 64 {
		return Processed{}, ErrProcessing
	}
	if _, err := hex.DecodeString(recognized.ExecutableSHA256); err != nil {
		return Processed{}, ErrProcessing
	}
	signals, err := p.analyzer.Analyze(ctx, recognized.Text)
	if err := ctx.Err(); err != nil {
		return Processed{}, err
	}
	if err != nil {
		return Processed{}, ErrProcessing
	}
	signals, err = contentproof.Freeze(recognized.Text, signals, 32768)
	if err != nil {
		return Processed{}, ErrProcessing
	}
	disposition := NeedsReview
	risk := 0
	for _, signal := range signals.Signals {
		if signal.Category == contentsignals.CategoryContact {
			disposition = ContactCorrection
		}
	}
	for _, score := range signals.Scores() {
		risk = max(risk, int(math.Ceil(score*100)))
	}
	metadata, err := jpeg.DecodeConfig(bytes.NewReader(normalized))
	if err != nil {
		return Processed{}, ErrProcessing
	}
	digest := sha256.Sum256(normalized)
	proof := struct {
		SourceID            string                `json:"source_id"`
		PipelineVersion     string                `json:"pipeline_version"`
		NormalizerVersion   string                `json:"normalizer_version"`
		SourceSHA256        string                `json:"source_sha256"`
		NormalizedSHA256    string                `json:"normalized_sha256"`
		Width               int                   `json:"width"`
		Height              int                   `json:"height"`
		OCRVersion          string                `json:"ocr_version"`
		OCRModelSHA256      string                `json:"ocr_model_sha256"`
		OCRExecutableSHA256 string                `json:"ocr_executable_sha256"`
		Analysis            contentsignals.Result `json:"analysis"`
		RiskScore           int                   `json:"risk_score"`
		Disposition         string                `json:"disposition"`
		PendingChecks       []string              `json:"pending_checks"`
	}{
		SourceID: source.id, PipelineVersion: p.version, NormalizerVersion: FullNormalizerVersion,
		SourceSHA256: hex.EncodeToString(source.digest[:]), NormalizedSHA256: hex.EncodeToString(digest[:]),
		Width: metadata.Width, Height: metadata.Height, OCRVersion: recognized.Version,
		OCRModelSHA256: recognized.ModelSHA256, OCRExecutableSHA256: recognized.ExecutableSHA256,
		Analysis: signals, RiskScore: risk, Disposition: disposition,
		PendingChecks: []string{"banned_image_similarity", "human_review"},
	}
	encoded, err := json.Marshal(proof)
	if err != nil || len(encoded) > 32768 {
		return Processed{}, ErrProcessing
	}
	if err := ctx.Err(); err != nil {
		return Processed{}, err
	}
	return Processed{image: normalized, assessment: encoded, digest: digest, disposition: disposition, risk: risk}, nil
}

func ocrLabel(value string) bool {
	return len(value) > 0 && len(value) <= 128 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}
