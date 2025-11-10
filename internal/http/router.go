package httpapi

import (
    "database/sql"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net/http"
    "strconv"
    "strings"
    "time"

    "github.com/cazocarma/rac-user-service/internal/config"
    "github.com/cazocarma/rac-user-service/internal/repo"
    "github.com/gin-gonic/gin"
)

type Server struct {
    db   *sql.DB
    repo *repo.Repo
    cfg  config.Config
}

func New(db *sql.DB, cfg config.Config) *Server { return &Server{db: db, repo: repo.New(db), cfg: cfg} }

func (s *Server) Router() *gin.Engine {
    r := gin.Default()

	// CORS mínimo para DEV
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Health
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "service": "rac-user-service"})
	})

    api := r.Group("/api/user")
    {
        // Compas
        api.GET("/compas", s.listCompas)       // ?limit=&offset=&skill=
        api.GET("/compas/:id", s.getCompaByID) // detalle

        // Skills
        api.GET("/skills", s.listSkills)                   // ?q=&limit=
        api.POST("/compas/:id/skills", s.addSkillsToCompa) // body: {"skills":["asado","karaoke"]}

        // Profile (requires Authorization Bearer)
        api.POST("/profile", s.upsertProfile)
    }

    return r
}

func (s *Server) listCompas(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	skill := strings.TrimSpace(c.Query("skill"))
	res, err := s.repo.ListCompas(c, limit, offset, skill)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, res)
}

func (s *Server) getCompaByID(c *gin.Context) {
	id := c.Param("id")
	item, err := s.repo.GetCompaByID(c, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, gin.H{"error": "not_found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
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
	// TODO: cuando integremos login, validar token y que id pertenezca al compa autenticado o que sea admin.
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
	if err := s.repo.AddSkillsToPerfil(c, id, req.Skills); err != nil {
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
    Nombre           string    `json:"nombre"`
    Correo           string    `json:"correo"`
    FechaNacimiento  string    `json:"fecha_nacimiento"`
    Genero           *string   `json:"genero"`
    Telefono         string    `json:"telefono"`
    Pais             string    `json:"pais"`
    Region           string    `json:"region"`
    Ciudad           string    `json:"ciudad"`
    Direccion        *string   `json:"direccion"`
    Intereses        []string  `json:"intereses"`
    IdiomaPreferido  *string   `json:"idioma_preferido"`
    Notificaciones   *bool     `json:"notificaciones_activadas"`
    FotoPerfil       *string   `json:"foto_perfil"`
    Ubicacion        *struct{ Lat float64 `json:"lat"`; Lon float64 `json:"lon"` } `json:"ubicacion"`
    RadioBusquedaKm  *int      `json:"radio_busqueda_km"`
}

func (s *Server) upsertProfile(c *gin.Context) {
    // Auth: call auth-service /userinfo
    tok := c.GetHeader("Authorization")
    if tok == "" { c.JSON(401, gin.H{"error":"no_token"}); return }
    req, _ := http.NewRequestWithContext(c, http.MethodGet, strings.TrimRight(s.cfg.AuthBaseURL, "/")+"/api/auth/userinfo", nil)
    req.Header.Set("Authorization", tok)
    res, err := http.DefaultClient.Do(req)
    if err != nil { c.JSON(502, gin.H{"error":"auth_unreachable"}); return }
    defer res.Body.Close()
    if res.StatusCode != 200 { b,_:=io.ReadAll(res.Body); c.JSON(401, gin.H{"error":"auth_invalid","body":string(b)}); return }
    var ui struct{ Sub string `json:"sub"`; Email string `json:"email"`; PreferredUsername string `json:"preferred_username"` }
    b, _ := io.ReadAll(res.Body)
    _ = json.Unmarshal(b, &ui)
    if ui.Sub == "" { c.JSON(401, gin.H{"error":"auth_no_sub"}); return }

    var body upsertProfileReq
    if err := c.BindJSON(&body); err != nil { c.JSON(400, gin.H{"error":"invalid_body"}); return }
    if strings.TrimSpace(body.Nombre) == "" || strings.TrimSpace(body.Correo) == "" || strings.TrimSpace(body.FechaNacimiento) == "" || strings.TrimSpace(body.Telefono) == "" || strings.TrimSpace(body.Pais) == "" || strings.TrimSpace(body.Region) == "" || strings.TrimSpace(body.Ciudad) == "" {
        c.JSON(400, gin.H{"error":"missing_required"}); return
    }
    // parse fecha
    var fNac sql.NullTime
    if t, err := time.Parse("2006-01-02", strings.Split(body.FechaNacimiento, "T")[0]); err == nil {
        fNac.Time = t; fNac.Valid = true
        // >=18
        if t.After(time.Now().AddDate(-18,0,0)) { c.JSON(400, gin.H{"error":"must_be_18_plus"}); return }
    } else { c.JSON(400, gin.H{"error":"invalid_fecha_nacimiento"}); return }

    // ubicacion WKT
    var wkt *string
    if body.Ubicacion != nil {
        sWKT := fmt.Sprintf("POINT(%f %f)", body.Ubicacion.Lon, body.Ubicacion.Lat)
        wkt = &sWKT
    }

    // call repo
    in := repo.ProfileInput{
        Nombre: body.Nombre, Correo: body.Correo, FechaNacimiento: fNac, Genero: body.Genero, Telefono: body.Telefono,
        Pais: body.Pais, Region: body.Region, Ciudad: body.Ciudad, Direccion: body.Direccion, Intereses: body.Intereses,
        IdiomaPreferido: body.IdiomaPreferido, Notificaciones: body.Notificaciones, FotoPerfil: body.FotoPerfil,
        UbicacionWKT: wkt, RadioBusquedaKm: body.RadioBusquedaKm,
    }
    if err := s.repo.UpsertProfileByKeycloak(c, ui.Sub, in); err != nil { c.JSON(500, gin.H{"error": err.Error()}); return }
    c.JSON(200, gin.H{"ok": true})
}
