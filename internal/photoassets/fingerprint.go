package photoassets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"math"
	"math/bits"
	"slices"
	"sort"

	"github.com/cazocarma/rac-platform/audit"
	"github.com/cazocarma/rac-user-service/internal/photos"
	"github.com/corona10/goimagehash"
	"github.com/disintegration/imaging"
)

// This version binds the library, crop set and low-information exclusions. It
// is not wire-compatible with other pHash implementations or crop policies.
const FingerprintVersion = "rac-goimagehash-1.1.0-crops/1"

type fingerprintView struct {
	name       string
	hash       uint64
	comparable bool
}
type Fingerprints struct {
	version string
	views   []fingerprintView
	digest  [32]byte
}

func (f Fingerprints) ImageDigest() [32]byte { return f.digest }

func (f Fingerprints) Comparable() bool { return len(f.views) > 0 && f.views[0].comparable }

// JSON returns private technical data; hexadecimal strings avoid uint64 loss
// in browser JSON consumers. It contains no user/case identifiers.
func (f Fingerprints) JSON() json.RawMessage {
	type view struct {
		Name       string `json:"view"`
		Hash       string `json:"hash"`
		Comparable bool   `json:"comparable"`
	}
	values := make([]view, 0, len(f.views))
	for _, v := range f.views {
		encoded := ""
		if v.comparable {
			encoded = fmt.Sprintf("%016x", v.hash)
		}
		values = append(values, view{v.name, encoded, v.comparable})
	}
	encoded, _ := json.Marshal(struct {
		Version     string `json:"version"`
		ImageSHA256 string `json:"image_sha256"`
		Views       []view `json:"views"`
	}{f.version, hex.EncodeToString(f.digest[:]), values})
	return encoded
}

func Fingerprint(ctx context.Context, normalized []byte) (Fingerprints, error) {
	if err := ctx.Err(); err != nil {
		return Fingerprints{}, err
	}
	if len(normalized) < 1 || len(normalized) > photos.MaxBytes {
		return Fingerprints{}, ErrInvalid
	}
	config, err := jpeg.DecodeConfig(bytes.NewReader(normalized))
	if err != nil || config.Width < 1 || config.Height < 1 || config.Width > 2048 || config.Height > 2048 {
		return Fingerprints{}, ErrInvalid
	}
	img, err := jpeg.Decode(bytes.NewReader(normalized))
	if err != nil {
		return Fingerprints{}, ErrInvalid
	}
	result := Fingerprints{version: FingerprintVersion, digest: sha256.Sum256(normalized)}
	for _, percent := range []int{100, 98, 96, 94, 92, 90} {
		if err := ctx.Err(); err != nil {
			return Fingerprints{}, err
		}
		bounds := img.Bounds()
		width := max(1, bounds.Dx()*percent/100)
		height := max(1, bounds.Dy()*percent/100)
		left := bounds.Min.X + (bounds.Dx()-width)/2
		top := bounds.Min.Y + (bounds.Dy()-height)/2
		// Keep a zero-origin frame for the hashing library's resize paths.
		frame := imaging.Crop(img, image.Rect(left, top, left+width, top+height))
		view := fingerprintView{name: fmt.Sprintf("center_%d", percent), comparable: informative(frame)}
		if view.comparable {
			hash, err := goimagehash.PerceptionHash(frame)
			if err != nil {
				return Fingerprints{}, ErrProcessing
			}
			view.hash = hash.GetHash()
		}
		result.views = append(result.views, view)
	}
	if err := ctx.Err(); err != nil {
		return Fingerprints{}, err
	}
	return result, nil
}

// Exclude weak signatures rather than matching blank/near-flat frames by their
// incidental DCT rounding noise. These technical cutoffs are part of version 1,
// not a legal/business match threshold; exclusions stay visible for human review.
func informative(img image.Image) bool {
	small := imaging.Resize(img, 32, 32, imaging.Box)
	histogram := [16]int{}
	sum, squares := 0.0, 0.0
	var pixels [32][32]float64
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			gray := color.GrayModel.Convert(small.At(x, y)).(color.Gray).Y
			value := float64(gray)
			pixels[y][x] = value
			sum += value
			squares += value * value
			histogram[int(gray)/16]++
		}
	}
	variance := math.Max(0, squares/1024-math.Pow(sum/1024, 2))
	entropy := 0.0
	for _, count := range histogram {
		if count > 0 {
			p := float64(count) / 1024
			entropy -= p * math.Log2(p)
		}
	}
	curvature := 0.0
	for y := 1; y < 31; y++ {
		for x := 1; x < 31; x++ {
			curvature += math.Abs(4*pixels[y][x] - pixels[y-1][x] - pixels[y+1][x] - pixels[y][x-1] - pixels[y][x+1])
		}
	}
	return math.Sqrt(variance) >= 6 && entropy >= 0.75 && curvature/900 >= 2.5
}

// Reference must originate from a reviewed case/evidence registry. UUID shape
// validation here does not prove that such a case was authorized: that is the
// responsibility of its owner ingress, not a caller-supplied approval boolean.
type ImageReference struct {
	ID, CaseID, EvidenceID string
	Fingerprints           Fingerprints
}
type SimilarityPolicy struct {
	Version                string
	MaxDistance, MatchRisk int
}
type ImageMatcher struct {
	policy     SimilarityPolicy
	references []ImageReference
}
type ImageMatch struct {
	ReferenceID string `json:"reference_id"`
	CaseID      string `json:"case_id"`
	EvidenceID  string `json:"evidence_id"`
	Distance    int    `json:"distance"`
}
type Similarity struct {
	PolicyVersion string       `json:"policy_version"`
	State         string       `json:"state"`
	Matches       []ImageMatch `json:"matches"`
}

func NewImageMatcher(policy SimilarityPolicy, references []ImageReference) (*ImageMatcher, error) {
	if !versionPattern.MatchString(policy.Version) || policy.MaxDistance < 0 || policy.MaxDistance > 64 || policy.MatchRisk < 1 || policy.MatchRisk > 100 || len(references) > 10000 {
		return nil, ErrInvalid
	}
	snapshot := slices.Clone(references)
	seen := map[string]bool{}
	for i, reference := range snapshot {
		if !audit.ValidID(reference.ID) || !audit.ValidID(reference.CaseID) || !audit.ValidID(reference.EvidenceID) || seen[reference.ID] || !validFingerprints(reference.Fingerprints) || !reference.Fingerprints.Comparable() {
			return nil, ErrInvalid
		}
		seen[reference.ID] = true
		snapshot[i].Fingerprints.views = slices.Clone(reference.Fingerprints.views)
	}
	sort.Slice(snapshot, func(i, j int) bool { return snapshot[i].ID < snapshot[j].ID })
	return &ImageMatcher{policy: policy, references: snapshot}, nil
}

func validFingerprints(f Fingerprints) bool {
	if f.version != FingerprintVersion || len(f.views) != 6 {
		return false
	}
	for i, percent := range []int{100, 98, 96, 94, 92, 90} {
		if f.views[i].name != fmt.Sprintf("center_%d", percent) {
			return false
		}
	}
	return true
}

func (m *ImageMatcher) Compare(ctx context.Context, query Fingerprints) (Similarity, error) {
	if err := ctx.Err(); err != nil {
		return Similarity{}, err
	}
	if !validFingerprints(query) {
		return Similarity{}, ErrInvalid
	}
	result := Similarity{PolicyVersion: m.policy.Version, State: "evaluated", Matches: []ImageMatch{}}
	if !query.Comparable() {
		result.State = "not_comparable"
		return result, nil
	}
	for _, reference := range m.references {
		if err := ctx.Err(); err != nil {
			return Similarity{}, err
		}
		distance := 64
		// Compare one full frame against the other's crop family. Comparing every
		// crop with every crop would multiply false-match opportunities unnecessarily.
		for _, view := range reference.Fingerprints.views {
			if view.comparable {
				distance = min(distance, bits.OnesCount64(query.views[0].hash^view.hash))
			}
		}
		for _, view := range query.views {
			if view.comparable {
				distance = min(distance, bits.OnesCount64(reference.Fingerprints.views[0].hash^view.hash))
			}
		}
		if distance <= m.policy.MaxDistance {
			result.Matches = append(result.Matches, ImageMatch{reference.ID, reference.CaseID, reference.EvidenceID, distance})
		}
	}
	sort.Slice(result.Matches, func(i, j int) bool {
		if result.Matches[i].Distance != result.Matches[j].Distance {
			return result.Matches[i].Distance < result.Matches[j].Distance
		}
		return result.Matches[i].ReferenceID < result.Matches[j].ReferenceID
	})
	return result, ctx.Err()
}
