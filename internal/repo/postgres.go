package repo

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
)

type Repo struct{ DB *sql.DB }

func New(db *sql.DB) *Repo { return &Repo{DB: db} }

type ProfileInput struct {
	Nombre          string
	Correo          string
	FechaNacimiento sql.NullTime
	Genero          *string
	Telefono        string
	Pais            string
	Region          string
	Ciudad          string
	Direccion       *string
	Intereses       []string
	IdiomaPreferido *string
	Notificaciones  *bool
	FotoPerfil      *string
	UbicacionWKT    *string
	RadioBusquedaKm *int
}

// UpsertProfileByKeycloak inserts or updates usuario by keycloak_id and fills extended fields
func (r *Repo) UpsertProfileByKeycloak(ctx context.Context, keycloakID string, in ProfileInput, beforeCommit ...func(context.Context, *sql.Tx) error) error {
	// Build geometry from WKT when provided
	var args []any
	q := `INSERT INTO usuario (id, nombre, correo, rol, keycloak_id, email_verified, fecha_nacimiento, genero, telefono, pais, region, ciudad, direccion, intereses, idioma_preferido, notificaciones_activadas, foto_perfil, ubicacion, radio_busqueda_km)
VALUES (gen_random_uuid(), $1, $2, 'cliente', $3, false, $4, $5, $6, $7, $8, $9, $10, $11, $12, COALESCE($13,false), $14, %s, $16)
ON CONFLICT (keycloak_id) DO UPDATE SET
  nombre=EXCLUDED.nombre,
  correo=COALESCE(EXCLUDED.correo, usuario.correo),
  fecha_nacimiento=EXCLUDED.fecha_nacimiento,
  genero=EXCLUDED.genero,
  telefono=EXCLUDED.telefono,
  pais=EXCLUDED.pais,
  region=EXCLUDED.region,
  ciudad=EXCLUDED.ciudad,
  direccion=EXCLUDED.direccion,
  intereses=EXCLUDED.intereses,
  idioma_preferido=EXCLUDED.idioma_preferido,
  notificaciones_activadas=EXCLUDED.notificaciones_activadas,
  foto_perfil=EXCLUDED.foto_perfil,
  ubicacion=EXCLUDED.ubicacion,
  radio_busqueda_km=EXCLUDED.radio_busqueda_km`
	ubisql := "ST_SetSRID(ST_GeomFromText($15),4326)"
	if in.UbicacionWKT != nil {
		ubisql = "ST_SetSRID(ST_GeomFromText($15),4326)"
	}
	q = fmt.Sprintf(q, ubisql)
	intereses := pq.StringArray(in.Intereses)
	args = []any{in.Nombre, in.Correo, keycloakID, in.FechaNacimiento, in.Genero, in.Telefono, in.Pais, in.Region, in.Ciudad, in.Direccion, intereses, in.IdiomaPreferido, in.Notificaciones, in.FotoPerfil}
	args = append(args, in.UbicacionWKT)
	args = append(args, in.RadioBusquedaKm)
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, q, args...); err != nil {
		return err
	}
	for _, check := range beforeCommit {
		if check != nil {
			if err = check(ctx, tx); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

type CompaCard struct {
	Biography      string     `json:"biografia"`
	Interests      []string   `json:"intereses"`
	ID             string     `json:"id"`
	UsuarioID      string     `json:"usuario_id"`
	Nombre         string     `json:"nombre"`
	TarifaHora     float64    `json:"tarifa_hora"`
	Actividades    []Activity `json:"actividades"`
	ReviewCount    int        `json:"cantidad_resenas"`
	RatingPromedio float64    `json:"rating_promedio"`
	FotoURL        *string    `json:"foto_url,omitempty"`
	Descripcion    *string    `json:"descripcion,omitempty"`
}

/*************** COMPAS ****************/

const compaColumns = `cp.id, cp.usuario_id, u.nombre, cp.tarifa_hora,
       COALESCE(rv.promedio,0), COALESCE(rv.cantidad,0), CASE WHEN u.foto_clave IS NOT NULL THEN '/api/user/media/profile/' || u.foto_clave END, cp.descripcion, u.biografia, COALESCE(u.intereses,'{}'::text[])
FROM compa_perfil cp
JOIN usuario u ON u.id = cp.usuario_id
LEFT JOIN LATERAL (SELECT avg(puntuacion)::float8 AS promedio,count(*) AS cantidad FROM reserva_resena WHERE compa_id=cp.usuario_id) rv ON true`

func scanCompa(scan func(...any) error) (CompaCard, error) {
	var c CompaCard
	var foto, desc sql.NullString
	err := scan(&c.ID, &c.UsuarioID, &c.Nombre, &c.TarifaHora,
		&c.RatingPromedio, &c.ReviewCount, &foto, &desc, &c.Biography, pq.Array(&c.Interests))
	if foto.Valid {
		c.FotoURL = &foto.String
	}
	if desc.Valid {
		c.Descripcion = &desc.String
	}
	c.Actividades = []Activity{}
	return c, err
}

// ListCompas serves discovery: only compas with an offered activity, filtered
// by an exact category slug. There is no free-text search over descriptions.
func (r *Repo) ListCompas(ctx context.Context, limit, offset int, category string, policy CatalogPolicy, enforceStanding bool) ([]CompaCard, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	q := `SELECT ` + compaColumns + `
WHERE ($1 = '' OR EXISTS (SELECT FROM compa_activities fa JOIN activity_categories c ON c.id=fa.category_id
 WHERE fa.compa_id=cp.id AND c.slug=$1 AND ` + visible(4) + `))` + offeredClause(4) + PublicStandingClause(enforceStanding) + `
ORDER BY COALESCE(rv.promedio,0) DESC, cp.tarifa_hora ASC NULLS LAST, cp.id ASC
LIMIT $2 OFFSET $3`
	rows, err := r.DB.QueryContext(ctx, q, category, limit, offset, policy.AllowProposed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]CompaCard, 0)
	ids := []string{}
	for rows.Next() {
		c, err := scanCompa(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		ids = append(ids, c.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	activities, err := r.activitiesFor(ctx, ids, policy)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if found := activities[out[i].ID]; found != nil {
			out[i].Actividades = found
		}
	}
	return out, nil
}

// GetCompaByID applies the discovery visibility rule when public; the owner's
// own view (public=false) also shows a profile without offered activities.
func (r *Repo) GetCompaByID(ctx context.Context, id string, policy CatalogPolicy, public, enforceStanding bool) (*CompaCard, error) {
	q := `SELECT ` + compaColumns + `
WHERE (cp.id::text = $1 OR cp.usuario_id::text = $1) AND (NOT $3 OR ` + offeredExists(2) + `)` + PublicStandingClause(enforceStanding) + `
LIMIT 1`
	c, err := scanCompa(r.DB.QueryRowContext(ctx, q, id, policy.AllowProposed, public).Scan)
	if err != nil {
		return nil, err
	}
	activities, err := r.activitiesFor(ctx, []string{c.ID}, policy)
	if err != nil {
		return nil, err
	}
	if found := activities[c.ID]; found != nil {
		c.Actividades = found
	}
	return &c, nil
}
