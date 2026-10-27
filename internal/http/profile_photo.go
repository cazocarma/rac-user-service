package httpapi

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/cazocarma/rac-platform/standing"
	"github.com/cazocarma/rac-user-service/internal/photos"
	"github.com/cazocarma/rac-user-service/internal/photostore"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/cazocarma/rac-user-service/internal/repo"
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

func (s *Server) photos() photostore.Store {
	if s.photoStore != nil {
		return s.photoStore
	}
	return photostore.Local{Directory: s.photoDirectory()}
}

func (s *Server) removePhotoObject(key string) {
	if !photoKey.MatchString(key) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := s.photos().Delete(ctx, key); err != nil {
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
	ctx, permit, cancel, ok := s.userPermit(c, standing.Requirement{Subject: platform.Principal(c).Subject, Capability: standing.PublishListing})
	defer cancel()
	if !ok {
		return
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared(726224,1)`); err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	var previous sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT foto_clave FROM usuario WHERE keycloak_id=$1 FOR UPDATE`, platform.Principal(c).Subject).Scan(&previous)
	if err == sql.ErrNoRows {
		c.JSON(409, gin.H{"error": "profile_required"})
		return
	}
	if err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	// Hold the current registry lease before the external object write and
	// through the DB commit that exposes the new photo.
	if err = s.lockedPublicProfileDocuments(ctx, tx, platform.Principal(c).Subject); err != nil {
		writeDocumentFailure(c, err)
		return
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	key := hex.EncodeToString(random[:]) + ".jpg"
	// Acquisition may reuse a bounded lease. Confirm fresh authority before
	// external object storage as well as before publishing its DB reference.
	if permit != nil {
		if err = permit.Check(ctx); err != nil {
			reviewStandingFailure(c, err)
			return
		}
	}
	if err = s.photos().Put(ctx, key, normalized); err != nil {
		// An uncertain remote write may leave an unreachable object. Never change
		// the DB pointer on failure; cleanup can be retried separately.
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	if _, err = tx.ExecContext(ctx, `UPDATE usuario SET foto_clave=$2 WHERE keycloak_id=$1`, platform.Principal(c).Subject, key); err != nil {
		s.removePhotoObject(key)
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	if permit != nil {
		if err = permit.Check(ctx); err != nil {
			s.removePhotoObject(key)
			reviewStandingFailure(c, err)
			return
		}
	}
	// Commit errors can have uncertain outcomes: retain the new object so a
	// committed reference cannot become broken. It is unreachable if rolled back.
	if err = tx.Commit(); err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
	if previous.Valid {
		s.removePhotoObject(previous.String)
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
	if _, err = tx.ExecContext(c.Request.Context(), `SELECT pg_advisory_xact_lock_shared(726224,1)`); err != nil {
		c.JSON(503, gin.H{"error": "photo_unavailable"})
		return
	}
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
		s.removePhotoObject(previous.String)
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
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT EXISTS(SELECT 1 FROM usuario u JOIN compa_perfil cp ON cp.usuario_id=u.id WHERE u.foto_clave=$1`+repo.PublicStandingClause(standingEnabled())+`)`, key).Scan(&exists)
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
	raw, err := s.photos().Get(c.Request.Context(), key)
	if errors.Is(err, photostore.ErrNotFound) {
		c.Status(404)
		return
	}
	if err != nil {
		c.Status(503)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Security-Policy", "default-src 'none'; sandbox")
	c.Data(200, "image/jpeg", raw)
}
