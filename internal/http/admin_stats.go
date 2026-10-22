package httpapi

import (
	"context"
	"github.com/gin-gonic/gin"
	"time"
)

// adminStats exposes aggregate counts only; no identities, messages or money.
func (s *Server) adminStats(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	var result struct {
		Total  int64 `json:"total"`
		Compas int64 `json:"compas"`
	}
	if err := s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM usuario), (SELECT count(*) FROM compa_perfil)`).Scan(&result.Total, &result.Compas); err != nil {
		c.JSON(503, gin.H{"error": "summary_unavailable"})
		return
	}
	c.JSON(200, result)
}
