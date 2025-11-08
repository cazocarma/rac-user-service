package repo

import (
	"context"
	"database/sql"
	"strings"

	"github.com/lib/pq"
)

type Repo struct{ DB *sql.DB }

func New(db *sql.DB) *Repo { return &Repo{DB: db} }

type CompaCard struct {
	ID             string   `json:"id"`
	UsuarioID      string   `json:"usuario_id"`
	Nombre         string   `json:"nombre"`
	TarifaHora     float64  `json:"tarifa_hora"`
	Habilidades    []string `json:"habilidades"`
	RatingPromedio float64  `json:"rating_promedio"`
	FotoURL        *string  `json:"foto_url,omitempty"`
	Descripcion    *string  `json:"descripcion,omitempty"`
}

/*************** COMPAS ****************/

func (r *Repo) ListCompas(ctx context.Context, limit, offset int, skill string) ([]CompaCard, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	q := `
SELECT cp.id, cp.usuario_id, u.nombre, cp.tarifa_hora, cp.habilidades_cache,
       cp.rating_promedio, cp.foto_url, cp.descripcion
FROM compa_perfil cp
JOIN usuario u ON u.id = cp.usuario_id
WHERE ($1 = '' OR $1 = ANY(cp.habilidades_cache))
ORDER BY cp.rating_promedio DESC NULLS LAST, cp.tarifa_hora ASC NULLS LAST
LIMIT $2 OFFSET $3`
	rows, err := r.DB.QueryContext(ctx, q, skill, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]CompaCard, 0)
	for rows.Next() {
		var c CompaCard
		var habilidades pq.StringArray
		var foto, desc sql.NullString
		if err := rows.Scan(
			&c.ID, &c.UsuarioID, &c.Nombre, &c.TarifaHora, &habilidades,
			&c.RatingPromedio, &foto, &desc,
		); err != nil {
			return nil, err
		}
		c.Habilidades = []string(habilidades)
		if foto.Valid {
			c.FotoURL = &foto.String
		}
		if desc.Valid {
			c.Descripcion = &desc.String
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *Repo) GetCompaByID(ctx context.Context, id string) (*CompaCard, error) {
	q := `
SELECT cp.id, cp.usuario_id, u.nombre, cp.tarifa_hora, cp.habilidades_cache,
       cp.rating_promedio, cp.foto_url, cp.descripcion
FROM compa_perfil cp
JOIN usuario u ON u.id = cp.usuario_id
WHERE cp.id = $1
LIMIT 1`
	var c CompaCard
	var habilidades pq.StringArray
	var foto, desc sql.NullString
	if err := r.DB.QueryRowContext(ctx, q, id).Scan(
		&c.ID, &c.UsuarioID, &c.Nombre, &c.TarifaHora, &habilidades,
		&c.RatingPromedio, &foto, &desc,
	); err != nil {
		return nil, err
	}
	c.Habilidades = []string(habilidades)
	if foto.Valid {
		c.FotoURL = &foto.String
	}
	if desc.Valid {
		c.Descripcion = &desc.String
	}
	return &c, nil
}

/*************** SKILLS ****************/

// ListSkills lista skills con filtro por prefijo (case-insensitive) y límite.
func (r *Repo) ListSkills(ctx context.Context, qtext string, limit int) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	qtext = strings.TrimSpace(qtext)
	query := `
SELECT s.name
FROM skill s
WHERE ($1 = '' OR LOWER(s.name) LIKE LOWER($1) || '%')
ORDER BY s.name ASC
LIMIT $2`
	rows, err := r.DB.QueryContext(ctx, query, qtext, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// AddSkillsToPerfil upsertea skills por nombre y crea las relaciones para un perfil.
func (r *Repo) AddSkillsToPerfil(ctx context.Context, perfilID string, skills []string) error {
	if len(skills) == 0 {
		return nil
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Normaliza: recorta, minúsculas básicas
	clean := make([]string, 0, len(skills))
	seen := map[string]struct{}{}
	for _, s := range skills {
		s2 := strings.TrimSpace(s)
		if s2 == "" {
			continue
		}
		s2 = strings.ToLower(s2)
		if _, ok := seen[s2]; ok {
			continue
		}
		seen[s2] = struct{}{}
		clean = append(clean, s2)
	}
	if len(clean) == 0 {
		return tx.Commit()
	}

	// Upsert skills y crear relaciones
	for _, name := range clean {
		var skillID string
		if err := tx.QueryRowContext(ctx, `
INSERT INTO skill (id, name)
VALUES (gen_random_uuid(), $1)
ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
RETURNING id
`, name).Scan(&skillID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO compa_perfil_skill (perfil_id, skill_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING
`, perfilID, skillID); err != nil {
			return err
		}
		// Trigger AFTER insert/udpate/delete recalcula habilidades_cache; por si acaso:
		if _, err := tx.ExecContext(ctx, `SELECT refresh_habilidades_cache($1)`, perfilID); err != nil {
			return err
		}
	}

	return tx.Commit()
}
