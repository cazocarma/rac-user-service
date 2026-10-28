package editorial

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cazocarma/rac-platform/audit"
	"github.com/cazocarma/rac-platform/staff"
	"github.com/cazocarma/rac-user-service/internal/attestations"
	"github.com/cazocarma/rac-user-service/internal/strictjson"
	"github.com/lib/pq"
)

const assessmentDraftSignature = "documents.draft_assessment(audit.reference,audit.reference,audit.reference,audit.reference,text,text,text,audit.digest)"
const assessmentReviewSignature = "documents.review_assessment(audit.reference,audit.reference,audit.reference,audit.reference,audit.digest,text)"
const assessmentPublishSignature = "documents.publish_assessment(audit.reference,audit.reference,audit.reference,audit.reference,audit.digest)"
const assessmentReadSignature = "documents.read_editorial_assessment(uuid)"
const bundleSignature = "documents.activate_editorial_bundle(audit.reference,bigint,text,uuid[],text[],audit.reference,audit.digest,audit.reference,audit.reference,text[])"

type assessmentDraftRequest struct {
	EventID      string               `json:"event_id"`
	DefinitionID string               `json:"definition_id"`
	Version      string               `json:"version"`
	Locale       string               `json:"locale"`
	Content      attestations.Content `json:"content"`
}
type assessmentCommand struct {
	EventID      string `json:"event_id"`
	DefinitionID string `json:"definition_id"`
	SHA256       string `json:"sha256"`
}
type assessmentReviewRequest struct {
	assessmentCommand
	Decision string `json:"decision"`
}

func validAssessment(c assessmentCommand) bool {
	return audit.ValidID(c.EventID) && audit.ValidID(c.DefinitionID) && digestPattern.MatchString(c.SHA256)
}
func (s *Server) draftAssessment(w http.ResponseWriter, r *http.Request) {
	var body assessmentDraftRequest
	if !decode(w, r, &body) {
		return
	}
	canonical, err := json.Marshal(body.Content)
	if err != nil || !audit.ValidID(body.EventID) || !audit.ValidID(body.DefinitionID) || !versionPattern.MatchString(body.Version) || (body.Locale != "es" && body.Locale != "en") || body.Content.Validate() != nil || len(canonical) > 65536 {
		problem(w, 400, "invalid_editorial_command")
		return
	}
	digest := body.Content.Digest()
	hash := hex.EncodeToString(digest[:])
	s.transact(w, r, staff.DocumentsDraft, func(ctx context.Context, tx *sql.Tx, actor, policy string) (any, error) {
		var id string
		err := tx.QueryRowContext(ctx, `SELECT documents.draft_assessment($1::audit.reference,$2::audit.reference,$3::audit.reference,$4::audit.reference,$5,$6,$7,$8::audit.digest)`, body.EventID, body.DefinitionID, actor, policy, body.Version, body.Locale, string(canonical), hash).Scan(&id)
		return map[string]string{"definition_id": id, "sha256": hash}, err
	})
}
func (s *Server) assessmentWrite(w http.ResponseWriter, r *http.Request, c assessmentCommand, decision string) {
	if !validAssessment(c) {
		problem(w, 400, "invalid_editorial_command")
		return
	}
	permission := staff.DocumentsPublish
	if decision != "" {
		permission = staff.DocumentsApprove
	}
	s.transact(w, r, permission, func(ctx context.Context, tx *sql.Tx, actor, policy string) (any, error) {
		var id string
		var err error
		if decision != "" {
			err = tx.QueryRowContext(ctx, `SELECT documents.review_assessment($1::audit.reference,$2::audit.reference,$3::audit.reference,$4::audit.reference,$5::audit.digest,$6)`, c.EventID, c.DefinitionID, actor, policy, c.SHA256, decision).Scan(&id)
		} else {
			err = tx.QueryRowContext(ctx, `SELECT documents.publish_assessment($1::audit.reference,$2::audit.reference,$3::audit.reference,$4::audit.reference,$5::audit.digest)`, c.EventID, c.DefinitionID, actor, policy, c.SHA256).Scan(&id)
		}
		return map[string]string{"definition_id": id}, err
	})
}
func (s *Server) reviewAssessment(w http.ResponseWriter, r *http.Request) {
	var body assessmentReviewRequest
	if !decode(w, r, &body) {
		return
	}
	if body.Decision != "approved" && body.Decision != "rejected" {
		problem(w, 400, "invalid_editorial_command")
		return
	}
	s.assessmentWrite(w, r, body.assessmentCommand, body.Decision)
}
func (s *Server) publishAssessment(w http.ResponseWriter, r *http.Request) {
	var body assessmentCommand
	if !decode(w, r, &body) {
		return
	}
	s.assessmentWrite(w, r, body, "")
}
func (s *Server) readAssessment(w http.ResponseWriter, r *http.Request) {
	s.readResource(w, r, "SELECT documents.read_editorial_assessment($1)")
}

type bundleDocument struct {
	ID     string `json:"document_id"`
	SHA256 string `json:"sha256"`
}
type bundleAssessment struct {
	ID     string `json:"definition_id"`
	SHA256 string `json:"sha256"`
}
type bundleRequest struct {
	EventID    string           `json:"event_id"`
	Expected   *int64           `json:"expected_version"`
	Locale     string           `json:"locale"`
	Documents  []bundleDocument `json:"documents"`
	Assessment bundleAssessment `json:"assessment"`
	Summary    []string         `json:"summary"`
}

func (b bundleRequest) valid() bool {
	if !audit.ValidID(b.EventID) || b.Expected == nil || *b.Expected < 0 || *b.Expected == math.MaxInt64 || (b.Locale != "es" && b.Locale != "en") || len(b.Documents) != 5 || !audit.ValidID(b.Assessment.ID) || !digestPattern.MatchString(b.Assessment.SHA256) || b.Summary == nil || len(b.Summary) > 3 {
		return false
	}
	seen := map[string]bool{}
	for _, d := range b.Documents {
		if !audit.ValidID(d.ID) || seen[d.ID] || !digestPattern.MatchString(d.SHA256) {
			return false
		}
		seen[d.ID] = true
	}
	for _, point := range b.Summary {
		if strings.TrimSpace(point) == "" || utf8.RuneCountInString(point) > 280 || strings.ContainsFunc(point, unicode.IsControl) {
			return false
		}
	}
	return true
}
func (s *Server) activateBundle(w http.ResponseWriter, r *http.Request) {
	var body bundleRequest
	if !decode(w, r, &body) {
		return
	}
	if !body.valid() {
		problem(w, 400, "invalid_editorial_command")
		return
	}
	s.transact(w, r, staff.DocumentsActivate, func(ctx context.Context, tx *sql.Tx, actor, policy string) (any, error) {
		// Approval cannot turn a malformed grading definition into a valid one.
		var raw []byte
		if err := tx.QueryRowContext(ctx, "SELECT documents.read_editorial_assessment($1)", body.Assessment.ID).Scan(&raw); err != nil {
			return nil, err
		}
		var stored struct {
			Content string `json:"content"`
			SHA256  string `json:"sha256"`
		}
		var content attestations.Content
		if json.Unmarshal(raw, &stored) != nil || stored.SHA256 != body.Assessment.SHA256 || strictjson.Decode(strings.NewReader(stored.Content), &content) != nil || content.Validate() != nil {
			return nil, &pq.Error{Code: "40001"}
		}
		digest := content.Digest()
		if hex.EncodeToString(digest[:]) != stored.SHA256 {
			return nil, &pq.Error{Code: "40001"}
		}
		ids, hashes := []string{}, []string{}
		for _, d := range body.Documents {
			ids = append(ids, d.ID)
			hashes = append(hashes, d.SHA256)
		}
		var version int64
		err := tx.QueryRowContext(ctx, `SELECT documents.activate_editorial_bundle($1::audit.reference,$2,$3,$4::uuid[],$5::text[],$6::audit.reference,$7::audit.digest,$8::audit.reference,$9::audit.reference,$10::text[])`, body.EventID, *body.Expected, body.Locale, pq.Array(ids), pq.Array(hashes), body.Assessment.ID, body.Assessment.SHA256, actor, policy, pq.Array(body.Summary)).Scan(&version)
		return map[string]int64{"registry_version": version}, err
	})
}
