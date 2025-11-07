package repo

import (
	"context"
	"database/sql"

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

func (r *Repo) ListCompas(ctx context.Context, limit int, skill string) ([]CompaCard, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	q := `
SELECT cp.id, cp.usuario_id, u.nombre, cp.tarifa_hora, cp.habilidades_cache,
       cp.rating_promedio, cp.foto_url, cp.descripcion
FROM compa_perfil cp
JOIN usuario u ON u.id = cp.usuario_id
WHERE ($1 = '' OR $1 = ANY(cp.habilidades_cache))
ORDER BY cp.rating_promedio DESC NULLS LAST, cp.tarifa_hora ASC NULLS LAST
LIMIT $2`

	rows, err := r.DB.QueryContext(ctx, q, skill, limit)
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
			&c.ID,
			&c.UsuarioID,
			&c.Nombre,
			&c.TarifaHora,
			&habilidades,
			&c.RatingPromedio,
			&foto,
			&desc,
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
