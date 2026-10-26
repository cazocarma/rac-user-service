package httpapi

import (
	"context"
	"database/sql"
	"github.com/cazocarma/rac-platform/standing"
	standingdb "github.com/cazocarma/rac-platform/standing/postgres"

	"errors"
	"fmt"

	"strconv"
	"strings"
	"time"

	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/photostore"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/cazocarma/rac-user-service/internal/repo"
	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
)

type Server struct {
	standingCache *standing.LeaseCache
	photoStore    photostore.Store
	photoDir      string
	db            *sql.DB
	repo          *repo.Repo
	cfg           config.Config
	security      *platform.Security
	grantCompa    func(context.Context, string) error
}

func New(db *sql.DB, cfg config.Config) *Server {
	return &Server{standingCache: standing.NewLeaseCache(standingdb.New(db)), db: db, repo: repo.New(db), cfg: cfg, security: platform.FromEnvironment(), grantCompa: platform.NewCompaProvisioner().Grant}
}

// SetPhotoStore configures persistence before Router is called.
func (s *Server) SetPhotoStore(store photostore.Store) { s.photoStore = store }

func (s *Server) Router() *gin.Engine {
	r := gin.New()

	platform.Observe(r, "rac-user-service", standing.Metrics(s.standingCache))
	var dependency func(context.Context) error
	if s.photoStore != nil {
		dependency = s.photoStore.Check
	}
	platform.Health(r, s.db, dependency)
	api := r.Group("/api/user")
	api.GET("/admin/summary", s.security.Require("admin"), s.adminStats)
	api.GET("/documents", s.documents)
	api.GET("/documents/:id", s.document)
	api.GET("/me/documents", s.security.Require("cliente"), s.documents)
	api.POST("/me/documents/acceptances", s.security.Require("cliente"), s.acceptDocuments)
	{
		// Compas
		api.GET("/compas", s.listCompas) // ?limit=&offset=&skill=
		api.GET("/compas/:id/reviews", s.publicReviews)
		api.GET("/bookings/:id/review", s.security.Require("cliente"), s.bookingReview)
		api.POST("/bookings/:id/review", s.security.Require("cliente"), s.saveReview)
		api.GET("/compas/:id", s.getCompaByID) // detalle

		// Skills
		api.GET("/skills", s.listSkills)                                                // ?q=&limit=
		api.POST("/compas/:id/skills", s.security.Require("compa"), s.addSkillsToCompa) // body: {"skills":["asado","karaoke"]}

		// Profile (requires Authorization Bearer)
		api.GET("/me", s.security.Require("cliente"), s.me)
		api.GET("/me/standing", s.security.Require("cliente"), s.ownStanding)
		api.PUT("/me", s.security.Require("cliente"), s.saveMe)
		api.GET("/me/photo", s.security.Require("cliente"), s.ownPhoto)
		api.PUT("/me/photo", s.security.Require("cliente"), s.savePhoto)
		api.DELETE("/me/photo", s.security.Require("cliente"), s.deletePhoto)
		api.GET("/media/profile/:key", s.publicPhoto)
		api.GET("/me/compa", s.security.Require("cliente"), s.ownCompa)
		api.PUT("/me/compa", s.security.Require("cliente"), s.saveOwnCompa)
		api.POST("/compas", s.security.Require("compa"), s.publishCompa)
		api.POST("/profile", s.security.Require("cliente"), s.upsertProfile)
	}

	return r
}

func (s *Server) listCompas(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	skill := strings.TrimSpace(c.Query("skill"))
	res, err := s.repo.ListCompas(c, limit, offset, skill, standingEnabled())
	if err != nil {
		c.JSON(503, gin.H{"error": "catalog_unavailable"})
		return
	}
	c.JSON(200, res)
}

func (s *Server) getCompaByID(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	id := c.Param("id")
	item, err := s.repo.GetCompaByID(c, id, standingEnabled())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, gin.H{"error": "not_found"})
			return
		}
		c.JSON(503, gin.H{"error": "catalog_unavailable"})
		return
	}
	c.JSON(200, item)
}

func (s *Server) listSkills(c *gin.Context) {
	q := strings.TrimSpace(c.DefaultQuery("q", ""))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	items, err := s.repo.ListSkills(c, q, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	// respuesta simple: array de strings
	c.JSON(200, items)
}

type addSkillsReq struct {
	Skills []string `json:"skills"`
}

func (s *Server) addSkillsToCompa(c *gin.Context) {
	p := platform.Principal(c)
	var owner string
	if err := s.db.QueryRowContext(c, "SELECT u.keycloak_id FROM compa_perfil cp JOIN usuario u ON u.id=cp.usuario_id WHERE cp.id::text=$1", c.Param("id")).Scan(&owner); err != nil {
		c.JSON(404, gin.H{"error": "not_found"})
		return
	}
	if !p.HasRole("admin") && owner != p.Subject {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	id := c.Param("id")
	var req addSkillsReq
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_body"})
		return
	}
	if len(req.Skills) == 0 {
		c.JSON(400, gin.H{"error": "no_skills"})
		return
	}
	ctx, permit, cancel, ok := s.userPermit(c, standing.Requirement{Subject: p.Subject, Capability: standing.PublishListing}, standing.Requirement{Subject: owner, Capability: standing.PublishListing})
	defer cancel()
	if !ok {
		return
	}
	check := func(ctx context.Context) error {
		if permit == nil {
			return nil
		}
		return permit.Check(ctx)
	}
	if err := s.repo.AddSkillsToPerfil(ctx, id, req.Skills, check); err != nil {
		if errors.Is(err, standing.ErrDenied) || errors.Is(err, standing.ErrUnavailable) {
			reviewStandingFailure(c, err)
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	// Devuelve el compa actualizado
	item, err := s.repo.GetCompaByID(c, id)
	if err != nil {
		c.JSON(200, gin.H{"ok": true})
		return
	}
	c.JSON(200, item)
}

// ==== Profile ====
type upsertProfileReq struct {
	Nombre          string   `json:"nombre"`
	Correo          string   `json:"correo"`
	FechaNacimiento string   `json:"fecha_nacimiento"`
	Genero          *string  `json:"genero"`
	Telefono        string   `json:"telefono"`
	Pais            string   `json:"pais"`
	Region          string   `json:"region"`
	Ciudad          string   `json:"ciudad"`
	Direccion       *string  `json:"direccion"`
	Intereses       []string `json:"intereses"`
	IdiomaPreferido *string  `json:"idioma_preferido"`
	Notificaciones  *bool    `json:"notificaciones_activadas"`
	FotoPerfil      *string  `json:"foto_perfil"`
	Ubicacion       *struct {
		Lat float64 `json:"lat"`
		Lon float64 `json:"lon"`
	} `json:"ubicacion"`
	RadioBusquedaKm *int `json:"radio_busqueda_km"`
}

func (s *Server) upsertProfile(c *gin.Context) {
	principal := platform.Principal(c)
	var body upsertProfileReq
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid_body"})
		return
	}
	if strings.TrimSpace(body.Nombre) == "" || strings.TrimSpace(body.Correo) == "" || strings.TrimSpace(body.FechaNacimiento) == "" || strings.TrimSpace(body.Telefono) == "" || strings.TrimSpace(body.Pais) == "" || strings.TrimSpace(body.Region) == "" || strings.TrimSpace(body.Ciudad) == "" {
		c.JSON(400, gin.H{"error": "missing_required"})
		return
	}
	// parse fecha
	var fNac sql.NullTime
	if t, err := time.Parse("2006-01-02", strings.Split(body.FechaNacimiento, "T")[0]); err == nil {
		fNac.Time = t
		fNac.Valid = true
		// >=18
		if t.After(time.Now().AddDate(-18, 0, 0)) {
			c.JSON(400, gin.H{"error": "must_be_18_plus"})
			return
		}
	} else {
		c.JSON(400, gin.H{"error": "invalid_fecha_nacimiento"})
		return
	}

	// ubicacion WKT
	var wkt *string
	if body.Ubicacion != nil {
		sWKT := fmt.Sprintf("POINT(%f %f)", body.Ubicacion.Lon, body.Ubicacion.Lat)
		wkt = &sWKT
	}

	// call repo
	in := repo.ProfileInput{
		Nombre: body.Nombre, Correo: principal.Email, FechaNacimiento: fNac, Genero: body.Genero, Telefono: body.Telefono,
		Pais: body.Pais, Region: body.Region, Ciudad: body.Ciudad, Direccion: body.Direccion, Intereses: body.Intereses,
		IdiomaPreferido: body.IdiomaPreferido, Notificaciones: body.Notificaciones, FotoPerfil: body.FotoPerfil,
		UbicacionWKT: wkt, RadioBusquedaKm: body.RadioBusquedaKm,
	}
	ctx := c.Request.Context()
	cancel := func() {}
	if standingEnabled() {
		ctx, cancel = context.WithTimeout(ctx, standing.MaxLease)
	}
	defer cancel()
	check := func(ctx context.Context, tx *sql.Tx) error {
		if !standingEnabled() {
			return nil
		}
		// New users receive standing through the same transaction's insert
		// trigger. Query that uncommitted authority locally; existing accounts
		// still observe current committed sanctions under READ COMMITTED.
		bounded, permit, cancel, err := standing.Acquire(ctx, standingdb.New(tx), standing.Requirement{Subject: principal.Subject, Capability: standing.PublishListing})
		defer cancel()
		if err != nil {
			return err
		}
		return permit.Check(bounded)
	}
	if err := s.repo.UpsertProfileByKeycloak(ctx, principal.Subject, in, check); err != nil {
		if errors.Is(err, standing.ErrDenied) || errors.Is(err, standing.ErrUnavailable) {
			reviewStandingFailure(c, err)
			return
		}
		c.JSON(503, gin.H{"error": "profile_unavailable"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (s *Server) me(c *gin.Context) {
	p := platform.Principal(c)
	var id, storedName, phone, country, region, city, biography, photoVersion string
	var interests []string
	name := p.Name
	if name == "" {
		name = p.Username
	}
	if name == "" {
		name = "Usuario"
	}
	if p.Email == "" {
		c.JSON(403, gin.H{"error": "email_required"})
		return
	}
	err := s.db.QueryRowContext(c, `INSERT INTO usuario(id,nombre,correo,rol,keycloak_id,verificado)
 VALUES(gen_random_uuid(),$1,$2,$3,$4,$5) ON CONFLICT(keycloak_id) DO UPDATE SET rol=EXCLUDED.rol,correo=EXCLUDED.correo,verificado=EXCLUDED.verificado RETURNING id::text,nombre,COALESCE(telefono,''),COALESCE(pais,''),COALESCE(region,''),COALESCE(ciudad,''),COALESCE(intereses,'{}'::text[]),biografia,COALESCE(foto_clave,'')`, name, p.Email, p.Role(), p.Subject, p.EmailVerified).Scan(&id, &storedName, &phone, &country, &region, &city, pq.Array(&interests), &biography, &photoVersion)
	if err != nil {
		c.JSON(409, gin.H{"error": "identity_conflict"})
		return
	}
	c.JSON(200, gin.H{"id": id, "sub": p.Subject, "nombre": storedName, "correo": p.Email, "role": p.Role(), "telefono": phone, "pais": country, "region": region, "ciudad": city, "intereses": interests, "biografia": biography, "foto_version": photoVersion})
}
func (s *Server) publishCompa(c *gin.Context) {
	p := platform.Principal(c)
	ctx, permit, cancel, ok := s.userPermit(c, standing.Requirement{Subject: p.Subject, Capability: standing.PublishListing})
	defer cancel()
	if !ok {
		return
	}
	var body struct {
		Descripcion string  `json:"descripcion"`
		Tarifa      float64 `json:"tarifa_hora"`
	}
	if c.ShouldBindJSON(&body) != nil || body.Tarifa < 0 {
		c.JSON(400, gin.H{"error": "invalid_body"})
		return
	}
	var id string
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		c.JSON(503, gin.H{"error": "profile_unavailable"})
		return
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `INSERT INTO compa_perfil(id,usuario_id,descripcion,tarifa_hora)
 SELECT gen_random_uuid(),id,$2,$3 FROM usuario WHERE keycloak_id=$1
 ON CONFLICT(usuario_id) DO UPDATE SET descripcion=EXCLUDED.descripcion,tarifa_hora=EXCLUDED.tarifa_hora RETURNING id::text`, p.Subject, body.Descripcion, body.Tarifa).Scan(&id)
	if err != nil {
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
	c.JSON(200, gin.H{"id": id})
}
