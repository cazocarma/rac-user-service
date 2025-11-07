package repo

import (
	"context"
	"database/sql"
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
	FotoURL        string   `json:"foto_url"`
	Descripcion    string   `json:"descripcion"`
}

func (r *Repo) ListCompas(ctx context.Context, limit int, skill string) ([]CompaCard, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	// Filtro rápido usando el cache habilidades_cache (definido en tu migración)
	q := `
SELECT cp.id, cp.usuario_id, u.nombre, cp.tarifa_hora, cp.habilidades_cache, cp.rating_promedio, cp.foto_url, cp.descripcion
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

	var out []CompaCard
	for rows.Next() {
		var c CompaCard
		if err := rows.Scan(&c.ID, &c.UsuarioID, &c.Nombre, &c.TarifaHora, &c.Habilidades, &c.RatingPromedio, &c.FotoURL, &c.Descripcion); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
