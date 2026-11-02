package photoassets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"math/rand"
	"slices"
	"sync"
	"testing"

	"github.com/disintegration/imaging"
)

func syntheticScene(seed int64) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 640, 480))
	random := rand.New(rand.NewSource(seed))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.RGBA{30, 80, 120, 255}), image.Point{}, draw.Src)
	for i := 0; i < 80; i++ {
		x, y := random.Intn(620), random.Intn(460)
		w, h := 20+random.Intn(220), 20+random.Intn(180)
		shade := color.RGBA{uint8(random.Intn(256)), uint8(random.Intn(256)), uint8(random.Intn(256)), 255}
		draw.Draw(img, image.Rect(x, y, min(640, x+w), min(480, y+h)), image.NewUniform(shade), image.Point{}, draw.Src)
	}
	return img
}
func encodedScene(t *testing.T, img image.Image, quality int) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := jpeg.Encode(&output, img, &jpeg.Options{Quality: quality}); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
func sceneFingerprints(t *testing.T, raw []byte) Fingerprints {
	t.Helper()
	value, err := Fingerprint(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func imageReference(f Fingerprints, id int) ImageReference {
	return ImageReference{ID: fmt.Sprintf("11111111-1111-4111-8111-%012d", id), CaseID: "22222222-2222-4222-8222-222222222222", EvidenceID: fmt.Sprintf("33333333-3333-4333-8333-%012d", id), Fingerprints: f}
}
func imagePolicy() SimilarityPolicy {
	return SimilarityPolicy{Version: "fixture-similarity-1", MaxDistance: 8, MatchRisk: 90}
}

func TestPerceptualSimilaritySyntheticCorpus(t *testing.T) {
	// Explicit synthetic threshold, not a reviewed production threshold or a
	// claim about natural images, faces, arbitrary crops or legal culpability.
	const originals = 24
	ctx := context.Background()
	references := make([]ImageReference, 0, originals)
	for i := 1; i <= originals; i++ {
		references = append(references, imageReference(sceneFingerprints(t, encodedScene(t, syntheticScene(int64(i)), 90)), i))
	}
	positives, matches, falseMatches, negatives := 0, 0, 0, 0
	for i := 1; i <= originals; i++ {
		matcher, err := NewImageMatcher(imagePolicy(), []ImageReference{references[i-1]})
		if err != nil {
			t.Fatal(err)
		}
		original := syntheticScene(int64(i))
		cropped := imaging.Crop(original, image.Rect(19, 14, 620, 465))
		decoded, err := jpeg.Decode(bytes.NewReader(encodedScene(t, original, 90)))
		if err != nil {
			t.Fatal(err)
		}
		variants := []image.Image{decoded, imaging.Resize(original, 320, 240, imaging.Lanczos), cropped,
			imaging.Crop(original, image.Rect(13, 10, 614, 461)),
			imaging.Crop(original, image.Rect(10, 16, 623, 467)),
			imaging.Crop(original, image.Rect(7, 7, 630, 471)),
		}
		for index, variant := range variants {
			query := sceneFingerprints(t, encodedScene(t, variant, 35+index*10))
			result, err := matcher.Compare(ctx, query)
			if err != nil {
				t.Fatal(err)
			}
			positives++
			if len(result.Matches) == 1 {
				matches++
			} else {
				t.Errorf("synthetic variant missed: seed=%d transform=%d state=%s", i, index, result.State)
			}
		}
		for j := i + 1; j <= originals; j++ {
			result, err := matcher.Compare(ctx, references[j-1].Fingerprints)
			if err != nil {
				t.Fatal(err)
			}
			negatives++
			if len(result.Matches) > 0 {
				falseMatches++
				t.Errorf("unrelated synthetic frames matched: %d/%d distance=%d", i, j, result.Matches[0].Distance)
			}
		}
	}
	t.Logf("synthetic corpus: positives=%d detected=%d negatives=%d false_matches=%d; threshold=8 (fixture only)", positives, matches, negatives, falseMatches)
}

func TestFingerprintExclusionsAndImmutablePolicy(t *testing.T) {
	ctx := context.Background()
	for _, policy := range []SimilarityPolicy{
		{Version: "", MaxDistance: 8, MatchRisk: 90},
		{Version: "fixture-1", MaxDistance: -1, MatchRisk: 90},
		{Version: "fixture-1", MaxDistance: 65, MatchRisk: 90},
		{Version: "fixture-1", MaxDistance: 8, MatchRisk: 0},
		{Version: "fixture-1", MaxDistance: 8, MatchRisk: 101},
	} {
		if _, err := NewImageMatcher(policy, nil); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid similarity policy accepted")
		}
	}
	for _, kind := range []string{"flat", "gradient"} {
		img := image.NewGray(image.Rect(0, 0, 640, 480))
		if kind == "gradient" {
			for y := 0; y < 480; y++ {
				for x := 0; x < 640; x++ {
					img.SetGray(x, y, color.Gray{uint8(x * 255 / 639)})
				}
			}
		}
		low := sceneFingerprints(t, encodedScene(t, img, 90))
		if low.Comparable() {
			t.Fatal("weak frame treated as reliable", kind)
		}
		if _, err := NewImageMatcher(imagePolicy(), []ImageReference{imageReference(low, 1)}); !errors.Is(err, ErrInvalid) {
			t.Fatal("weak banned reference accepted")
		}
		matcher, _ := NewImageMatcher(imagePolicy(), nil)
		result, err := matcher.Compare(ctx, low)
		if err != nil || result.State != "not_comparable" || len(result.Matches) > 0 {
			t.Fatal("excluded frame became a match or clean result", err)
		}
	}
	good := sceneFingerprints(t, encodedScene(t, syntheticScene(1), 90))
	query := good
	query.views = slices.Clone(good.views)
	references := []ImageReference{imageReference(good, 1)}
	matcher, err := NewImageMatcher(imagePolicy(), references)
	if err != nil {
		t.Fatal(err)
	}
	references[0].CaseID = "changed"
	references[0].Fingerprints.views[0].hash ^= 0xffff
	result, err := matcher.Compare(ctx, query)
	if err != nil || len(result.Matches) != 1 || result.Matches[0].Distance != 0 || result.Matches[0].CaseID != "22222222-2222-4222-8222-222222222222" {
		t.Fatal("caller changed frozen case/signature association", err)
	}
	for _, change := range []func(*ImageReference){
		func(r *ImageReference) { r.CaseID = "" }, func(r *ImageReference) { r.EvidenceID = "" }, func(r *ImageReference) { r.Fingerprints.version = "unsupported" },
	} {
		reference := imageReference(sceneFingerprints(t, encodedScene(t, syntheticScene(1), 90)), 1)
		change(&reference)
		if _, err := NewImageMatcher(imagePolicy(), []ImageReference{reference}); !errors.Is(err, ErrInvalid) {
			t.Fatal("untraceable/incompatible reference accepted")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Fingerprint(cancelled, encodedScene(t, syntheticScene(1), 90)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled fingerprint succeeded")
	}
}

func TestFingerprintConcurrencyAndSignalOnlyDisposition(t *testing.T) {
	raw := encodedScene(t, syntheticScene(2), 90)
	expected := sceneFingerprints(t, raw).JSON()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := Fingerprint(context.Background(), raw)
			if err != nil || !bytes.Equal(f.JSON(), expected) {
				t.Error("concurrent library hash changed", err)
			}
		}()
	}
	wg.Wait()
	upload, err := Prepare(context.Background(), raw, "image/jpeg", "fixture-pipeline-1")
	if err != nil {
		t.Fatal(err)
	}
	// Reference exactly the normalized version used by the processor.
	baseline, _ := NewProcessor("fixture-pipeline-1", ocrFunc(func(context.Context, []byte) (OCRResult, error) { return ocrFixture("Cine y museos"), nil }), engineFixture(t))
	reader := readerFunc(func(context.Context, string) ([]byte, error) { return upload.Bytes(), nil })
	first, err := baseline.Process(context.Background(), upload.Source(), reader)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := NewImageMatcher(imagePolicy(), []ImageReference{imageReference(sceneFingerprints(t, first.Image()), 1)})
	if err != nil {
		t.Fatal(err)
	}
	processor, _ := NewProcessor("fixture-pipeline-1", ocrFunc(func(context.Context, []byte) (OCRResult, error) { return ocrFixture("Cine y museos"), nil }), engineFixture(t), matcher)
	result, err := processor.Process(context.Background(), upload.Source(), reader)
	if err != nil || result.Disposition() != NeedsReview || result.RiskScore() != 90 {
		t.Fatal("image match became approval/sanction or lost priority", err)
	}
	var proof struct {
		Pending    []string   `json:"pending_checks"`
		Similarity Similarity `json:"similarity"`
	}
	if json.Unmarshal(result.Assessment(), &proof) != nil || len(proof.Similarity.Matches) != 1 || !slices.Contains(proof.Pending, "human_review") || slices.Contains(proof.Pending, "banned_image_similarity") {
		t.Fatal("match provenance/review state lost")
	}
}
