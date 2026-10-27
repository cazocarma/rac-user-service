package httpapi

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cazocarma/rac-platform/standing"
	"github.com/cazocarma/rac-user-service/internal/attestations"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
)

type assessmentDefinition struct {
	ID string
	attestations.Definition
}

func assessmentFailure(c *gin.Context) { c.JSON(503, gin.H{"error": "attestations_unavailable"}) }

// Caller holds the document-head lease until its read/write transaction ends.
func readAssessment(ctx context.Context, tx *sql.Tx, locale string) (assessmentDefinition, error) {
	var result assessmentDefinition
	var content string
	var digest []byte
	result.Locale = locale
	err := tx.QueryRowContext(ctx, "SELECT registry_version,policy_version FROM documents.lock_registry($1)", locale).
		Scan(&result.RegistryVersion, &result.PolicyVersion)
	if err != nil {
		return result, err
	}
	err = tx.QueryRowContext(ctx, `SELECT d.id,d.version,d.content,d.content_sha256,d.approved_by,d.reviewed_at,d.published_at
 FROM compa_attestation_requirements r JOIN compa_attestation_versions d ON d.id=r.definition_id
 WHERE r.locale=$1 AND r.registry_version=$2 AND d.legal_review='approved'
 AND d.published_at<=statement_timestamp()`, locale, result.RegistryVersion).
		Scan(&result.ID, &result.Version, &content, &digest, &result.ApprovedBy, &result.ReviewedAt, &result.PublishedAt)
	if err != nil {
		return result, err
	}
	if len(digest) != 32 {
		return result, attestations.ErrUnavailable
	}
	copy(result.SHA256[:], digest)
	result.Approved = true
	if decodeUniqueJSON(strings.NewReader(content), &result.Content) != nil {
		return result, attestations.ErrUnavailable
	}
	return result, result.Validate(time.Now())
}
func assessmentLocale(c *gin.Context) (string, bool) {
	locale := c.DefaultQuery("locale", "es")
	if locale != "es" && locale != "en" {
		c.JSON(400, gin.H{"error": "unsupported_locale"})
		return "", false
	}
	return locale, true
}
func (s *Server) ownAssessment(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	locale, ok := assessmentLocale(c)
	if !ok {
		return
	}
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		assessmentFailure(c)
		return
	}
	defer tx.Rollback()
	definition, err := readAssessment(c.Request.Context(), tx, locale)
	if err != nil {
		assessmentFailure(c)
		return
	}
	view, err := definition.Public(time.Now())
	if err != nil {
		assessmentFailure(c)
		return
	}
	var passed sql.NullTime
	err = tx.QueryRowContext(c.Request.Context(), `SELECT a.quiz_passed_at FROM usuario u
 LEFT JOIN compa_attestations a ON a.user_id=u.id AND a.definition_id=$2
 WHERE u.keycloak_id=$1`, platform.Principal(c).Subject, definition.ID).Scan(&passed)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(404, gin.H{"error": "profile_not_found"})
		return
	}
	if err != nil || tx.Commit() != nil {
		assessmentFailure(c)
		return
	}
	var at any
	if passed.Valid {
		at = passed.Time
	}
	c.JSON(200, gin.H{"version": definition.Version, "sha256": hex.EncodeToString(definition.SHA256[:]),
		"registry":   registryReference{Locale: locale, Version: definition.RegistryVersion, PolicyVersion: definition.PolicyVersion},
		"statements": view.Statements, "questions": view.Questions, "quiz_passed_at": at})
}

type assessmentRequest struct {
	Version    string            `json:"version"`
	SHA256     string            `json:"sha256"`
	Registry   registryReference `json:"registry"`
	Statements map[string]bool   `json:"statements"`
	Answers    map[string]string `json:"answers"`
}

func (s *Server) submitAssessment(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var input assessmentRequest
	if decodeUniqueJSON(http.MaxBytesReader(c.Writer, c.Request.Body, 8192), &input) != nil || input.Registry.Version == 0 ||
		!standing.ValidAccountID(input.Registry.PolicyVersion) || (input.Registry.Locale != "es" && input.Registry.Locale != "en") {
		c.JSON(400, gin.H{"error": "invalid_attestation"})
		return
	}
	hash, err := hex.DecodeString(input.SHA256)
	if err != nil || len(hash) != 32 {
		c.JSON(400, gin.H{"error": "invalid_attestation"})
		return
	}
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		assessmentFailure(c)
		return
	}
	defer tx.Rollback()
	definition, err := readAssessment(c.Request.Context(), tx, input.Registry.Locale)
	if err != nil {
		assessmentFailure(c)
		return
	}
	if definition.RegistryVersion != input.Registry.Version || definition.PolicyVersion != strings.ToLower(input.Registry.PolicyVersion) {
		c.JSON(409, gin.H{"error": "attestation_version_changed"})
		return
	}
	submission := attestations.Submission{Version: input.Version, Statements: input.Statements, Answers: input.Answers}
	copy(submission.SHA256[:], hash)
	if _, err = attestations.Evaluate(definition.Definition, submission, time.Now()); err != nil {
		switch {
		case errors.Is(err, attestations.ErrChanged):
			c.JSON(409, gin.H{"error": "attestation_version_changed"})
		case errors.Is(err, attestations.ErrDeclarations):
			c.JSON(422, gin.H{"error": "declarations_required"})
		case errors.Is(err, attestations.ErrQuiz):
			c.JSON(422, gin.H{"error": "quiz_incorrect"})
		default:
			assessmentFailure(c)
		}
		return
	}
	var user string
	if err = tx.QueryRowContext(c.Request.Context(), "SELECT id FROM usuario WHERE keycloak_id=$1", platform.Principal(c).Subject).Scan(&user); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, gin.H{"error": "profile_not_found"})
		} else {
			assessmentFailure(c)
		}
		return
	}
	statements, _ := json.Marshal(input.Statements)
	answers, _ := json.Marshal(input.Answers)
	_, err = tx.ExecContext(c.Request.Context(), `INSERT INTO compa_attestations(user_id,definition_id,locale,registry_version,policy_version,statements,answers)
 VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb) ON CONFLICT(user_id,definition_id) DO NOTHING`, user, definition.ID, definition.Locale, definition.RegistryVersion, definition.PolicyVersion, string(statements), string(answers))
	if err != nil {
		assessmentFailure(c)
		return
	}
	var at time.Time
	if err = tx.QueryRowContext(c.Request.Context(), "SELECT quiz_passed_at FROM compa_attestations WHERE user_id=$1 AND definition_id=$2", user, definition.ID).Scan(&at); err != nil || tx.Commit() != nil {
		assessmentFailure(c)
		return
	}
	c.JSON(200, gin.H{"version": definition.Version, "quiz_passed_at": at})
}
