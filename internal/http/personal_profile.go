package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cazocarma/rac-platform/standing"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
)

// Complete replacement of editable personal fields only. Identity, role and
// compa publication fields are deliberately absent from this contract.
type personalProfile struct {
	Name      string   `json:"nombre"`
	Biography string   `json:"biografia"`
	Phone     string   `json:"telefono"`
	Country   string   `json:"pais"`
	Region    string   `json:"region"`
	City      string   `json:"ciudad"`
	Interests []string `json:"intereses"`
}

func (p *personalProfile) valid() bool {
	for _, field := range []struct {
		value *string
		max   int
	}{{&p.Name, 120}, {&p.Phone, 30}, {&p.Country, 80}, {&p.Region, 100}, {&p.City, 100}} {
		*field.value = strings.TrimSpace(*field.value)
		if utf8.RuneCountInString(*field.value) > field.max || strings.ContainsFunc(*field.value, unicode.IsControl) {
			return false
		}
	}
	if utf8.RuneCountInString(p.Name) < 2 || len(p.Interests) > 15 {
		return false
	}
	p.Biography = strings.TrimSpace(p.Biography)
	if utf8.RuneCountInString(p.Biography) > 600 || strings.ContainsFunc(p.Biography, func(r rune) bool { return unicode.IsControl(r) && r != '\n' }) {
		return false
	}
	digits := 0
	for _, char := range p.Phone {
		if char >= '0' && char <= '9' {
			digits++
		}
	}
	if p.Phone != "" && (digits < 6 || strings.ContainsFunc(p.Phone, func(r rune) bool { return !strings.ContainsRune("0123456789+()- ", r) })) {
		return false
	}
	clean := make([]string, 0, len(p.Interests))
	seen := map[string]bool{}
	for _, interest := range p.Interests {
		interest = strings.TrimSpace(interest)
		if interest == "" || utf8.RuneCountInString(interest) > 40 || strings.ContainsFunc(interest, unicode.IsControl) {
			return false
		}
		key := strings.ToLower(interest)
		if !seen[key] {
			clean = append(clean, interest)
			seen[key] = true
		}
	}
	p.Interests = clean
	return true
}

func (s *Server) saveMe(c *gin.Context) {
	var body personalProfile
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 8192))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF || !body.valid() {
		c.JSON(400, gin.H{"error": "invalid_profile"})
		return
	}
	ctx, permit, cancel, ok := s.userPermit(c, standing.Requirement{Subject: platform.Principal(c).Subject, Capability: standing.PublishListing})
	defer cancel()
	if !ok {
		return
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		c.JSON(503, gin.H{"error": "profile_unavailable"})
		return
	}
	defer tx.Rollback()
	// Subject always comes from the verified token, never from the request body.
	result, err := tx.ExecContext(ctx, `UPDATE usuario SET nombre=$2,telefono=NULLIF($3,''),pais=NULLIF($4,''),region=NULLIF($5,''),ciudad=NULLIF($6,''),intereses=$7,biografia=$8 WHERE keycloak_id=$1`, platform.Principal(c).Subject, body.Name, body.Phone, body.Country, body.Region, body.City, pq.Array(body.Interests), body.Biography)
	if err != nil {
		c.JSON(503, gin.H{"error": "profile_unavailable"})
		return
	}
	count, err := result.RowsAffected()
	if err != nil {
		c.JSON(503, gin.H{"error": "profile_unavailable"})
		return
	}
	if count == 0 {
		c.JSON(409, gin.H{"error": "profile_required"})
		return
	}
	if permit != nil {
		if err = permit.Check(ctx); err != nil {
			reviewStandingFailure(c, err)
			return
		}
	}
	if err = tx.Commit(); err != nil {
		c.JSON(503, gin.H{"error": "profile_unavailable"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
