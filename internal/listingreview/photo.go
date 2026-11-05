package listingreview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/cazocarma/rac-platform/audit"
	"github.com/cazocarma/rac-platform/staff"
	"github.com/cazocarma/rac-user-service/internal/photostore"
)

const photoSignature = "listing_review.photo(audit.reference,audit.reference,audit.reference,audit.reference)"

// PreviewStore has no mutation or public URL operation. Its runtime identity
// must additionally be restricted to GetObject on private normalized staging.
type PreviewStore interface {
	Get(context.Context, string) ([]byte, error)
}

// SetPhotoPreview is a startup-only injection. Without an explicitly configured
// private store the route stays unavailable; no fallback to profile avatars.
func (s *Server) SetPhotoPreview(store PreviewStore) {
	s.photos = store
	s.photoSlots = make(chan struct{}, 2)
}

type previewReference struct {
	Revision       string `json:"revision_id"`
	Version        string `json:"listing_version"`
	RevisionDigest string `json:"revision_sha256"`
	Key            string `json:"object_key"`
	Digest         string `json:"sha256"`
	Size           int    `json:"size"`
}

var previewKey = regexp.MustCompile(`^[a-f0-9]{32}\.jpg$`)

func (s *Server) photoReference(ctx context.Context, session staff.Session, revision string) (previewReference, error) {
	id, err := eventID()
	if err != nil {
		return previewReference{}, errUnavailable
	}
	raw, err := s.transaction(ctx, session, staff.ListingsRead,
		`SELECT listing_review.photo($1,$2,$3,$4)`, id, session.Subject, s.policy, revision)
	if err != nil {
		return previewReference{}, err
	}
	var ref previewReference
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ref, photostore.ErrNotFound
	}
	if json.Unmarshal(raw, &ref) != nil || ref.Revision != revision || !previewKey.MatchString(ref.Key) ||
		!reviewDigest.MatchString(ref.Digest) || !reviewDigest.MatchString(ref.RevisionDigest) ||
		!decimalVersion.MatchString(ref.Version) || ref.Size < 1 || ref.Size > photostore.MaxStoredBytes {
		return previewReference{}, errUnavailable
	}
	return ref, nil
}

func (s *Server) photo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !audit.ValidID(id) || !noBody(r) || r.URL.RawQuery != "" || r.URL.ForceQuery {
		problem(w, 400, "invalid_listing_review_query")
		return
	}
	if s.photos == nil {
		problem(w, 503, "listing_review_unavailable")
		return
	}
	select {
	case s.photoSlots <- struct{}{}:
		defer func() { <-s.photoSlots }()
	default:
		problem(w, 503, "listing_review_unavailable")
		return
	}
	session, ok := staff.Principal(r.Context())
	if !ok {
		problem(w, 401, "staff_authentication_required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	ref, err := s.photoReference(ctx, session, id)
	if errors.Is(err, photostore.ErrNotFound) {
		problem(w, 404, "listing_photo_not_found")
		return
	}
	if err != nil {
		reviewFailure(w, err)
		return
	}
	// No transaction or business lock is held while reading private storage.
	body, err := s.photos.Get(ctx, ref.Key)
	if err != nil {
		problem(w, 503, "listing_review_unavailable")
		return
	}
	digest := sha256.Sum256(body)
	if len(body) != ref.Size || len(body) > photostore.MaxStoredBytes || len(body) < 3 ||
		!bytes.Equal(body[:3], []byte{0xff, 0xd8, 0xff}) || hex.EncodeToString(digest[:]) != ref.Digest {
		problem(w, 503, "listing_review_unavailable")
		return
	}
	// A second committed resolution closes revision/version and MFA changes
	// during I/O. Its audit commits before any image bytes reach the browser.
	current, err := s.photoReference(ctx, session, id)
	if err != nil || current != ref {
		if err != nil && !errors.Is(err, photostore.ErrNotFound) {
			reviewFailure(w, err)
		} else {
			problem(w, 404, "listing_photo_not_found")
		}
		return
	}
	if err := session.Check(staff.ListingsRead, s.now()); err != nil {
		reviewFailure(w, err)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `inline; filename="review.jpg"`)
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Write(body)
}
