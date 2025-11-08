package httpapi

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/cazocarma/rac-user-service/internal/repo"
	"github.com/gin-gonic/gin"
)

type Server struct {
	db   *sql.DB
	repo *repo.Repo
}

func New(db *sql.DB) *Server { return &Server{db: db, repo: repo.New(db)} }

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
