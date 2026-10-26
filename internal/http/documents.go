package httpapi

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cazocarma/rac-platform/standing"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
)

type documentView struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`
	Version        string     `json:"version"`
	Locale         string     `json:"locale"`
	SHA256         string     `json:"sha256"`
	MaterialChange bool       `json:"material_change"`
	PublishedAt    time.Time  `json:"published_at"`
	AcceptedAt     *time.Time `json:"accepted_at,omitempty"`
	Content        string     `json:"content,omitempty"`
}

func documentFailure(c *gin.Context) { c.JSON(503, gin.H{"error": "documents_unavailable"}) }

// Current documents contain only published, reviewed content. Reading them and
// recording consent are protective account actions, independent of standing.
func (s *Server) documents(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	locale := c.DefaultQuery("locale", "es")
	if locale != "es" && locale != "en" {
		c.JSON(400, gin.H{"error": "unsupported_locale"})
		return
	}
	var subject any
	if c.FullPath() == "/api/user/me/documents" {
		subject = platform.Principal(c).Subject
	}
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT DISTINCT ON(d.kind) d.id,d.kind,d.version,d.locale,encode(d.content_sha256,'hex'),d.material_change,d.published_at,a.accepted_at
 FROM legal_documents d LEFT JOIN usuario u ON u.keycloak_id=$2
 LEFT JOIN document_acceptances a ON a.user_id=u.id AND a.document_id=d.id
 WHERE d.locale=$1 AND d.legal_review='approved' AND d.published_at<=statement_timestamp()
 ORDER BY d.kind,d.published_at DESC,d.created_at DESC,d.id`, locale, subject)
	if err != nil {
		documentFailure(c)
		return
	}
	defer rows.Close()
	items := []documentView{}
	for rows.Next() {
		var item documentView
		if rows.Scan(&item.ID, &item.Kind, &item.Version, &item.Locale, &item.SHA256, &item.MaterialChange, &item.PublishedAt, &item.AcceptedAt) != nil {
			documentFailure(c)
			return
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		documentFailure(c)
		return
	}
	c.JSON(200, gin.H{"items": items})
}

func (s *Server) document(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if !standing.ValidAccountID(c.Param("id")) {
		c.JSON(404, gin.H{"error": "document_not_found"})
		return
	}
	var item documentView
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT id,kind,version,locale,encode(content_sha256,'hex'),material_change,published_at,content FROM legal_documents
 WHERE id=$1 AND legal_review='approved' AND published_at<=statement_timestamp()`, c.Param("id")).
		Scan(&item.ID, &item.Kind, &item.Version, &item.Locale, &item.SHA256, &item.MaterialChange, &item.PublishedAt, &item.Content)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(404, gin.H{"error": "document_not_found"})
		return
	}
	if err != nil {
		documentFailure(c)
		return
	}
	c.JSON(200, item)
}

type acceptanceRequest struct {
	Documents []struct {
		ID     string `json:"id"`
		SHA256 string `json:"sha256"`
	} `json:"documents"`
	Context string `json:"context"`
}

func (s *Server) acceptDocuments(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var input acceptanceRequest
	d := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 8192))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF || len(input.Documents) < 1 || len(input.Documents) > 5 ||
		(input.Context != "account" && input.Context != "compa_onboarding" && input.Context != "booking") {
		c.JSON(400, gin.H{"error": "invalid_document_acceptance"})
		return
	}
	seen := map[string]bool{}
	for _, item := range input.Documents {
		hash, err := hex.DecodeString(item.SHA256)
		key := strings.ToLower(item.ID)
		if !standing.ValidAccountID(item.ID) || seen[key] || err != nil || len(hash) != 32 {
			c.JSON(400, gin.H{"error": "invalid_document_acceptance"})
			return
		}
		seen[key] = true
	}
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		documentFailure(c)
		return
	}
	defer tx.Rollback()
	var user string
	if err = tx.QueryRowContext(c.Request.Context(), `SELECT id FROM usuario WHERE keycloak_id=$1`, platform.Principal(c).Subject).Scan(&user); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, gin.H{"error": "profile_not_found"})
		} else {
			documentFailure(c)
		}
		return
	}
	for _, item := range input.Documents {
		var available bool
		if err = tx.QueryRowContext(c.Request.Context(), `SELECT EXISTS(SELECT FROM legal_documents WHERE id=$1 AND content_sha256=decode($2,'hex')
 AND legal_review='approved' AND published_at<=statement_timestamp())`, item.ID, item.SHA256).Scan(&available); err != nil {
			documentFailure(c)
			return
		}
		if !available {
			c.JSON(409, gin.H{"error": "document_version_unavailable"})
			return
		}
		if _, err = tx.ExecContext(c.Request.Context(), `INSERT INTO document_acceptances(user_id,document_id,context) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, user, item.ID, input.Context); err != nil {
			documentFailure(c)
			return
		}
	}
	if tx.Commit() != nil {
		documentFailure(c)
		return
	}
	c.JSON(200, gin.H{"accepted": len(input.Documents)})
}
