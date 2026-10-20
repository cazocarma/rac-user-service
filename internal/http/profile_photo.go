package httpapi

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/cazocarma/rac-user-service/internal/photos"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
)

var photoKey = regexp.MustCompile(`^[a-f0-9]{32}\.jpg$`)
var photoSlots = make(chan struct{}, 2)

func (s *Server) photoDirectory() string {
	if s.photoDir != "" {
		return s.photoDir
	}
	if dir := os.Getenv("PROFILE_PHOTO_DIR"); dir != "" {
		return dir
	}
	return "/var/lib/rac/photos"
}

func (s *Server) removePhotoFile(key string) {
	if !photoKey.MatchString(key) {
		return
	}
	if err := os.Remove(filepath.Join(s.photoDirectory(), key)); err != nil && !os.IsNotExist(err) {
		log.Print("profile_photo_cleanup_failed")
	}
}

func (s *Server) savePhoto(c *gin.Context) {
	select {
	case photoSlots <- struct{}{}:
		defer func() { <-photoSlots }()
	default:
		c.JSON(429, gin.H{"error": "photo_busy"})
		return
	}
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || (mediaType != "image/jpeg" && mediaType != "image/png") {
		c.JSON(415, gin.H{"error": "photo_format"})
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, photos.MaxBytes))
	if err != nil {
		c.JSON(413, gin.H{"error": "photo_size"})
		return
	}
	normalized, err := photos.Normalize(raw, mediaType)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	defer tx.Rollback()
	var previous sql.NullString
	err = tx.QueryRowContext(c.Request.Context(), `SELECT foto_clave FROM usuario WHERE keycloak_id=$1 FOR UPDATE`, platform.Principal(c).Subject).Scan(&previous)
	if err == sql.ErrNoRows {
		c.JSON(409, gin.H{"error": "profile_required"})
		return
	}
	if err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	if err = os.MkdirAll(s.photoDirectory(), 0700); err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	key := hex.EncodeToString(random[:]) + ".jpg"
	path := filepath.Join(s.photoDirectory(), key)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	_, writeErr := file.Write(normalized)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		s.removePhotoFile(key)
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	if _, err = tx.ExecContext(c.Request.Context(), `UPDATE usuario SET foto_clave=$2 WHERE keycloak_id=$1`, platform.Principal(c).Subject, key); err != nil {
		s.removePhotoFile(key)
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	// Commit errors can have uncertain outcomes: retain the new file so a
	// committed reference cannot become broken. It is unreachable if rolled back.
	if err = tx.Commit(); err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	if previous.Valid {
		s.removePhotoFile(previous.String)
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"foto_version": key})
}

func (s *Server) deletePhoto(c *gin.Context) {
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	defer tx.Rollback()
	var previous sql.NullString
	err = tx.QueryRowContext(c.Request.Context(), `SELECT foto_clave FROM usuario WHERE keycloak_id=$1 FOR UPDATE`, platform.Principal(c).Subject).Scan(&previous)
	if err == sql.ErrNoRows {
		c.JSON(409, gin.H{"error": "profile_required"})
		return
	}
	if err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	if _, err = tx.ExecContext(c.Request.Context(), `UPDATE usuario SET foto_clave=NULL WHERE keycloak_id=$1`, platform.Principal(c).Subject); err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	if err = tx.Commit(); err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	if previous.Valid {
		s.removePhotoFile(previous.String)
	}
	c.JSON(200, gin.H{"ok": true})
}

func (s *Server) ownPhoto(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var key sql.NullString
	if s.db.QueryRowContext(c.Request.Context(), `SELECT foto_clave FROM usuario WHERE keycloak_id=$1`, platform.Principal(c).Subject).Scan(&key) != nil || !key.Valid {
		c.Status(404)
		return
	}
	s.servePhoto(c, key.String)
}

func (s *Server) publicPhoto(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	key := c.Param("key")
	if !photoKey.MatchString(key) {
		c.Status(404)
		return
	}
	var exists bool
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT EXISTS(SELECT 1 FROM usuario u JOIN compa_perfil cp ON cp.usuario_id=u.id WHERE u.foto_clave=$1)`, key).Scan(&exists)
	if err != nil {
		c.Status(503)
		return
	}
	if !exists {
		c.Status(404)
		return
	}
	s.servePhoto(c, key)
}

func (s *Server) servePhoto(c *gin.Context, key string) {
	if !photoKey.MatchString(key) {
		c.Status(404)
		return
	}
	raw, err := os.ReadFile(filepath.Join(s.photoDirectory(), key))
	if err != nil {
		c.Status(404)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Security-Policy", "default-src 'none'; sandbox")
	c.Data(200, "image/jpeg", raw)
}
