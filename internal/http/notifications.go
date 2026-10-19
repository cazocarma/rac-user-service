package httpapi

import (
	"database/sql"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
	"strconv"
	"time"
)

type notification struct {
	ID        string     `json:"id"`
	SessionID string     `json:"sesion_id"`
	Type      string     `json:"tipo"`
	Title     string     `json:"titulo"`
	Created   time.Time  `json:"creado_en"`
	Read      *time.Time `json:"leido_en"`
}

func (s *Server) notifications(c *gin.Context) {
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, offsetErr := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if err != nil || offsetErr != nil || limit < 1 || limit > 100 || offset < 0 {
		c.JSON(400, gin.H{"error": "invalid_pagination"})
		return
	}
	rows, err := s.db.QueryContext(c, `SELECT n.id::text,n.sesion_id::text,n.tipo,n.titulo,n.creado_en,n.leido_en
 FROM notificacion n JOIN usuario u ON u.id=n.usuario_id WHERE u.keycloak_id=$1
 ORDER BY n.creado_en DESC,n.id DESC LIMIT $2 OFFSET $3`, platform.Principal(c).Subject, limit+1, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": "notifications_unavailable"})
		return
	}
	defer rows.Close()
	items := make([]notification, 0)
	for rows.Next() {
		var item notification
		if err := rows.Scan(&item.ID, &item.SessionID, &item.Type, &item.Title, &item.Created, &item.Read); err != nil {
			c.JSON(500, gin.H{"error": "notifications_unavailable"})
			return
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		c.JSON(500, gin.H{"error": "notifications_unavailable"})
		return
	}
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	c.JSON(200, gin.H{"items": items, "has_more": more})
}

func (s *Server) readNotification(c *gin.Context) {
	var id string
	err := s.db.QueryRowContext(c, `UPDATE notificacion n SET leido_en=COALESCE(n.leido_en,now())
 FROM usuario u WHERE u.id=n.usuario_id AND u.keycloak_id=$1 AND n.id::text=$2 RETURNING n.id::text`,
		platform.Principal(c).Subject, c.Param("id")).Scan(&id)
	if err == sql.ErrNoRows {
		c.JSON(404, gin.H{"error": "not_found"})
		return
	}
	if err != nil {
		c.JSON(500, gin.H{"error": "notifications_unavailable"})
		return
	}
	c.JSON(200, gin.H{"id": id})
}
