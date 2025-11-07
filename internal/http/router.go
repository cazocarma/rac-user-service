package httpapi

import (
	"database/sql"
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

	// CORS simple para dev
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "service": "rac-user-service"})
	})

	api := r.Group("/api/user")
	{
		api.GET("/compas", s.listCompas) // público por ahora
	}
	return r
}

func (s *Server) listCompas(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	skill := strings.TrimSpace(c.Query("skill")) // ej: ?skill=karaoke
	res, err := s.repo.ListCompas(c, limit, skill)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, res)
}
