package httpapi

import (
	"database/sql"
	"encoding/json"
	"github.com/cazocarma/rac-platform/documents"
	"github.com/cazocarma/rac-platform/standing"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
)

var reviewBookingID = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)

type reviewInput struct {
	Score   int    `json:"puntuacion"`
	Comment string `json:"comentario"`
}
type reviewView struct {
	Score   int       `json:"puntuacion"`
	Comment string    `json:"comentario"`
	Created time.Time `json:"creado_en"`
}

func (s *Server) saveReview(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if !reviewBookingID.MatchString(c.Param("id")) {
		c.JSON(400, gin.H{"error": "invalid_booking"})
		return
	}
	var in reviewInput
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 8192))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		c.JSON(400, gin.H{"error": "invalid_review"})
		return
	}
	in.Comment = strings.TrimSpace(in.Comment)
	if in.Score < 1 || in.Score > 5 || utf8.RuneCountInString(in.Comment) > 1000 || strings.ContainsFunc(in.Comment, func(r rune) bool { return unicode.IsControl(r) && r != '\n' }) {
		c.JSON(400, gin.H{"error": "invalid_review"})
		return
	}
	ctx, permit, cancel, ok := s.reviewPermit(c)
	defer cancel()
	if !ok {
		return
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		c.JSON(503, gin.H{"error": "review_unavailable"})
		return
	}
	defer tx.Rollback()
	var client, compa, state string
	var end time.Time
	err = tx.QueryRowContext(ctx, `SELECT se.cliente_id::text,se.compa_id::text,se.estado::text,se.fecha_fin FROM lock_booking($1,$2,false) se JOIN usuario u ON u.id=se.cliente_id WHERE u.keycloak_id=$2`, c.Param("id"), platform.Principal(c).Subject).Scan(&client, &compa, &state, &end)
	if err == sql.ErrNoRows {
		c.JSON(404, gin.H{"error": "booking_not_found"})
		return
	}
	if err != nil {
		c.JSON(503, gin.H{"error": "review_unavailable"})
		return
	}
	if state != "finalizada" || end.After(time.Now()) || client == compa {
		c.JSON(409, gin.H{"error": "review_not_eligible"})
		return
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO reserva_resena(sesion_id,cliente_id,compa_id,puntuacion,comentario) VALUES($1,$2,$3,$4,$5) ON CONFLICT(sesion_id) DO NOTHING`, c.Param("id"), client, compa, in.Score, in.Comment)
	if err != nil {
		c.JSON(503, gin.H{"error": "review_unavailable"})
		return
	}
	var view reviewView
	if err = tx.QueryRowContext(ctx, `SELECT puntuacion,comentario,creado_en FROM reserva_resena WHERE sesion_id=$1`, c.Param("id")).Scan(&view.Score, &view.Comment, &view.Created); err != nil {
		c.JSON(503, gin.H{"error": "review_unavailable"})
		return
	}
	if view.Score != in.Score || view.Comment != in.Comment {
		c.JSON(409, gin.H{"error": "already_reviewed"})
		return
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		c.JSON(503, gin.H{"error": "review_unavailable"})
		return
	}
	if !s.documentCommit(ctx, c, tx, documents.Client, standing.WriteReview) {
		return
	}
	if permit != nil {
		if err = permit.Check(ctx); err != nil {
			reviewStandingFailure(c, err)
			return
		}
	}
	if err = tx.Commit(); err != nil {
		c.JSON(503, gin.H{"error": "review_unavailable"})
		return
	}
	status := 200
	if inserted == 1 {
		status = 201
	}
	c.JSON(status, view)
}
func (s *Server) bookingReview(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if !reviewBookingID.MatchString(c.Param("id")) {
		c.JSON(400, gin.H{"error": "invalid_booking"})
		return
	}
	var exists bool
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT EXISTS(SELECT 1 FROM sesion se JOIN usuario u ON (u.id=se.cliente_id OR u.id=se.compa_id) WHERE se.id=$1 AND u.keycloak_id=$2)`, c.Param("id"), platform.Principal(c).Subject).Scan(&exists)
	if err != nil {
		c.Status(503)
		return
	}
	if !exists {
		c.Status(404)
		return
	}
	var out reviewView
	err = s.db.QueryRowContext(c.Request.Context(), `SELECT puntuacion,comentario,creado_en FROM reserva_resena WHERE sesion_id=$1`, c.Param("id")).Scan(&out.Score, &out.Comment, &out.Created)
	if err == sql.ErrNoRows {
		c.JSON(200, gin.H{"resena": nil})
		return
	}
	if err != nil {
		c.Status(503)
		return
	}
	c.JSON(200, gin.H{"resena": out})
}
func (s *Server) publicReviews(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	compa, err := s.repo.GetCompaByID(c.Request.Context(), c.Param("id"), standingEnabled())
	if err == sql.ErrNoRows {
		c.Status(404)
		return
	}
	if err != nil {
		c.Status(503)
		return
	}
	offset := 0
	if raw := c.Query("offset"); raw != "" {
		var parseErr error
		offset, parseErr = strconv.Atoi(raw)
		if parseErr != nil {
			c.Status(400)
			return
		}
	}
	if offset < 0 || offset > 10000 {
		c.Status(400)
		return
	}
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT r.puntuacion,r.comentario,r.creado_en FROM reserva_resena r WHERE r.compa_id=$1 ORDER BY r.creado_en DESC,r.sesion_id LIMIT 20 OFFSET $2`, compa.UsuarioID, offset)
	if err != nil {
		c.Status(503)
		return
	}
	defer rows.Close()
	out := make([]reviewView, 0)
	for rows.Next() {
		var v reviewView
		if rows.Scan(&v.Score, &v.Comment, &v.Created) != nil {
			c.Status(503)
			return
		}
		out = append(out, v)
	}
	if rows.Err() != nil {
		c.Status(503)
		return
	}
	c.JSON(200, gin.H{"items": out, "total": compa.ReviewCount, "promedio": compa.RatingPromedio})
}
