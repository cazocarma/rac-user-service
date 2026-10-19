package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
	_ "time/tzdata"
	"unicode/utf8"
)

type compaProfile struct {
	TimeZone     string              `json:"zona_horaria"`
	Description  string              `json:"descripcion"`
	Rate         float64             `json:"tarifa_hora"`
	Skills       []string            `json:"habilidades"`
	Availability map[string][]string `json:"availability"`
}

func (p *compaProfile) validate() error {
	if p.TimeZone != "" {
		if p.TimeZone == "Local" {
			return errors.New("invalid_timezone")
		}
		if _, err := time.LoadLocation(p.TimeZone); err != nil {
			return errors.New("invalid_timezone")
		}
	}
	p.Description = strings.TrimSpace(p.Description)
	if utf8.RuneCountInString(p.Description) < 20 || utf8.RuneCountInString(p.Description) > 1500 || math.IsNaN(p.Rate) || math.IsInf(p.Rate, 0) || p.Rate < 0 || p.Rate > 99999999.99 || math.Abs(p.Rate*100-math.Round(p.Rate*100)) > 0.00001 {
		return errors.New("invalid_profile")
	}
	if len(p.Skills) < 1 || len(p.Skills) > 8 {
		return errors.New("invalid_skills")
	}
	seen := map[string]bool{}
	clean := []string{}
	for _, skill := range p.Skills {
		skill = strings.ToLower(strings.TrimSpace(skill))
		if utf8.RuneCountInString(skill) < 2 || utf8.RuneCountInString(skill) > 40 || strings.ContainsAny(skill, "\n\r\t") {
			return errors.New("invalid_skills")
		}
		if !seen[skill] {
			clean = append(clean, skill)
			seen[skill] = true
		}
	}
	sort.Strings(clean)
	p.Skills = clean
	days := map[string]bool{"lunes": true, "martes": true, "miercoles": true, "jueves": true, "viernes": true, "sabado": true, "domingo": true}
	count := 0
	for day, windows := range p.Availability {
		if !days[day] || len(windows) > 3 {
			return errors.New("invalid_availability")
		}
		sort.Strings(windows)
		previous := ""
		for _, window := range windows {
			parts := strings.Split(window, "-")
			if len(parts) != 2 || len(parts[0]) != 5 || len(parts[1]) != 5 {
				return errors.New("invalid_availability")
			}
			start, e1 := time.Parse("15:04", parts[0])
			end, e2 := time.Parse("15:04", parts[1])
			if e1 != nil || e2 != nil || !end.After(start) || (previous != "" && parts[0] < previous) {
				return errors.New("invalid_availability")
			}
			previous = parts[1]
			count++
		}
	}
	if count == 0 {
		return errors.New("availability_required")
	}
	return nil
}

func (s *Server) ownCompa(c *gin.Context) {
	var id string
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT id::text FROM usuario WHERE keycloak_id=$1`, platform.Principal(c).Subject).Scan(&id)
	if err == sql.ErrNoRows {
		c.JSON(404, gin.H{"error": "profile_required"})
		return
	}
	if err != nil {
		c.JSON(500, gin.H{"error": "profile_unavailable"})
		return
	}
	item, err := s.repo.GetCompaByID(c, id)
	if err == sql.ErrNoRows {
		c.JSON(404, gin.H{"error": "not_compa"})
		return
	}
	if err != nil {
		c.JSON(500, gin.H{"error": "profile_unavailable"})
		return
	}
	var raw []byte
	zona := "UTC"
	err = s.db.QueryRowContext(c.Request.Context(), `SELECT disponibilidad_json,zona_horaria FROM compa_availability WHERE compa_id=$1`, id).Scan(&raw, &zona)
	availability := map[string][]string{}
	if err != nil && err != sql.ErrNoRows {
		c.JSON(500, gin.H{"error": "profile_unavailable"})
		return
	}
	if len(raw) > 0 && json.Unmarshal(raw, &availability) != nil {
		c.JSON(500, gin.H{"error": "profile_unavailable"})
		return
	}
	c.JSON(200, gin.H{"profile": item, "availability": availability, "zona_horaria": zona})
}

func (s *Server) saveOwnCompa(c *gin.Context) {
	principal := platform.Principal(c)
	var body compaProfile
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16384)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		c.JSON(400, gin.H{"error": "invalid_body"})
		return
	}
	if err := body.validate(); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		c.JSON(503, gin.H{"error": "profile_unavailable"})
		return
	}
	defer tx.Rollback()
	var userID string
	// Serialize own profile edits. No caller-provided user id or role is accepted.
	err = tx.QueryRowContext(ctx, `SELECT id::text FROM usuario WHERE keycloak_id=$1 FOR UPDATE`, principal.Subject).Scan(&userID)
	if err == sql.ErrNoRows {
		c.JSON(409, gin.H{"error": "profile_required"})
		return
	}
	if err != nil {
		c.JSON(503, gin.H{"error": "profile_unavailable"})
		return
	}
	var profileID string
	err = tx.QueryRowContext(ctx, `INSERT INTO compa_perfil(id,usuario_id,descripcion,tarifa_hora) VALUES(gen_random_uuid(),$1,$2,$3)
 ON CONFLICT(usuario_id) DO UPDATE SET descripcion=EXCLUDED.descripcion,tarifa_hora=EXCLUDED.tarifa_hora RETURNING id::text`, userID, body.Description, body.Rate).Scan(&profileID)
	if err != nil {
		c.JSON(503, gin.H{"error": "profile_unavailable"})
		return
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM compa_perfil_skill WHERE perfil_id=$1`, profileID); err != nil {
		c.JSON(503, gin.H{"error": "profile_unavailable"})
		return
	}
	for _, skill := range body.Skills {
		_, err = tx.ExecContext(ctx, `WITH entry AS (INSERT INTO skill(id,name) VALUES(gen_random_uuid(),$2) ON CONFLICT(name) DO UPDATE SET name=EXCLUDED.name RETURNING id)
 INSERT INTO compa_perfil_skill(perfil_id,skill_id) SELECT $1,id FROM entry`, profileID, skill)
		if err != nil {
			c.JSON(503, gin.H{"error": "profile_unavailable"})
			return
		}
	}
	raw, _ := json.Marshal(body.Availability)
	if _, err = tx.ExecContext(ctx, `INSERT INTO compa_availability(compa_id,disponibilidad_json,zona_horaria) VALUES($1,$2::jsonb,COALESCE(NULLIF($3,''),'UTC'))
 ON CONFLICT(compa_id) DO UPDATE SET disponibilidad_json=EXCLUDED.disponibilidad_json,zona_horaria=COALESCE(NULLIF($3,''),compa_availability.zona_horaria),actualizado_en=now()`, userID, string(raw), body.TimeZone); err != nil {
		c.JSON(503, gin.H{"error": "profile_unavailable"})
		return
	}
	if !principal.HasRole("compa") {
		if err = s.grantCompa(ctx, principal.Subject); err != nil {
			c.JSON(503, gin.H{"error": "activation_unavailable"})
			return
		}
	}
	// Remote role assignment is idempotent. A failed commit can be retried safely;
	// no profile is visible before commit, and only the free compa role was granted.
	if err = tx.Commit(); err != nil {
		c.JSON(503, gin.H{"error": "profile_unavailable"})
		return
	}
	c.JSON(200, gin.H{"id": profileID, "usuario_id": userID, "refresh_session": !principal.HasRole("compa")})
}
