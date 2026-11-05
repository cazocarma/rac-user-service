package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/cazocarma/rac-platform/standing"
	"github.com/cazocarma/rac-user-service/internal/photoassets"
	"github.com/cazocarma/rac-user-service/internal/photos"
	"github.com/cazocarma/rac-user-service/internal/photostore"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/cazocarma/rac-user-service/internal/secretfile"
	"github.com/gin-gonic/gin"
)

// SetPrivatePhotoUploads configures the private owner API before Router. It
// never changes legacy avatar storage or enables public media/review approval.
func (s *Server) SetPrivatePhotoUploads(store photoassets.UploadStore, policy photoassets.UploadPolicy) error {
	uploads, err := photoassets.NewUploads(s.db, store, policy, s.photoSourceTransaction)
	if err != nil {
		return err
	}
	s.photoUploads = uploads
	s.photoUploadSlots = make(chan struct{}, 2)
	return nil
}

func (s *Server) ConfigurePrivatePhotoUploadsFromEnvironment() error {
	enabled := os.Getenv("RAC_PHOTO_UPLOADS_ENABLED")
	if enabled == "" || enabled == "false" {
		return nil
	}
	if enabled != "true" || os.Getenv("RAC_ENV") != "dev" {
		return photoassets.ErrInvalid
	}
	maximum, err := strconv.Atoi(os.Getenv("RAC_PHOTO_UPLOADS_PER_DAY"))
	if err != nil {
		return photoassets.ErrInvalid
	}
	access, err := secretfile.ReadEnvironment("RAC_PHOTO_INGEST_ACCESS_KEY")
	if err != nil {
		return err
	}
	secret, err := secretfile.ReadEnvironment("RAC_PHOTO_INGEST_SECRET_KEY")
	if err != nil {
		return err
	}
	bucket := os.Getenv("RAC_PHOTO_QUARANTINE_BUCKET")
	if bucket == os.Getenv("PROFILE_S3_BUCKET") || access == os.Getenv("PROFILE_S3_ACCESS_KEY") {
		return photoassets.ErrInvalid
	}
	store, err := photostore.NewQuarantineS3(os.Getenv("RAC_PHOTO_S3_ENDPOINT"), os.Getenv("RAC_PHOTO_S3_REGION"), bucket, access, secret)
	if err != nil {
		return err
	}
	return s.SetPrivatePhotoUploads(store, photoassets.UploadPolicy{Pipeline: os.Getenv("RAC_PHOTO_PIPELINE_VERSION"), MaxPerDay: maximum})
}

func (s *Server) photoSourceTransaction(ctx context.Context, subject string, work func(context.Context, *sql.Tx) error) error {
	if subject == "" {
		return photoassets.ErrInvalid
	}
	bounded := ctx
	cancel := func() {}
	var permit *standing.Permit
	var err error
	if standingEnabled() {
		bounded, permit, cancel, err = standing.Acquire(ctx, s.standingCache, standing.Requirement{Subject: subject, Capability: standing.PublishListing})
		if err != nil {
			return err
		}
	}
	defer cancel()
	tx, err := s.db.BeginTx(bounded, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return photoassets.ErrStorage
	}
	defer tx.Rollback()
	if err := work(bounded, tx); err != nil {
		return err
	}
	if err := s.lockedPublicProfileDocuments(bounded, tx, subject); err != nil {
		return err
	}
	if permit != nil {
		if err := permit.Check(bounded); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return photoassets.ErrStorage
	}
	return nil
}

func (s *Server) sourceAPIAvailable(c *gin.Context) bool {
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	if s.photoUploads == nil {
		c.JSON(503, gin.H{"error": "photo_upload_unavailable"})
		return false
	}
	return true
}

func (s *Server) photoUploadConfig(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"enabled": s.photoUploads != nil, "max_bytes": photos.MaxBytes, "formats": []string{"image/jpeg", "image/png"}})
}

func writePhotoSourceFailure(c *gin.Context, receipt photoassets.UploadStatus, err error) {
	if receipt.AssetID != "" {
		c.Header("Location", "/api/user/me/photo-sources/"+receipt.AssetID)
	}
	if isDocumentFailure(err) {
		writeDocumentFailure(c, err)
		return
	}
	if errors.Is(err, standing.ErrDenied) || errors.Is(err, standing.ErrUnavailable) {
		reviewStandingFailure(c, err)
		return
	}
	status, code := 503, "photo_upload_unavailable"
	switch {
	case errors.Is(err, photoassets.ErrInvalid):
		status, code = 400, "invalid_photo_upload"
	case errors.Is(err, photoassets.ErrNotFound):
		status, code = 404, "photo_source_not_found"
	case errors.Is(err, photoassets.ErrRequestConflict):
		status, code = 409, "photo_upload_request_conflict"
	case errors.Is(err, photoassets.ErrQuota):
		status, code = 429, "photo_upload_quota_exceeded"
	case errors.Is(err, photoassets.ErrIntegrity):
		status, code = 409, "photo_upload_integrity_mismatch"
	}
	body := gin.H{"error": code}
	if receipt.AssetID != "" {
		body["asset_id"] = receipt.AssetID
		body["resumable"] = !errors.Is(err, photoassets.ErrIntegrity)
	}
	c.JSON(status, body)
}

func (s *Server) uploadPhotoSource(c *gin.Context) {
	if !s.sourceAPIAvailable(c) {
		return
	}
	select {
	case s.photoUploadSlots <- struct{}{}:
		defer func() { <-s.photoUploadSlots }()
	default:
		c.JSON(429, gin.H{"error": "photo_upload_busy"})
		return
	}
	requestID := c.GetHeader("Idempotency-Key")
	if len(c.Request.Header.Values("Idempotency-Key")) != 1 || !photoassets.UUID(requestID) {
		c.JSON(400, gin.H{"error": "invalid_upload_request_id"})
		return
	}
	media, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || (media != "image/jpeg" && media != "image/png") {
		c.JSON(415, gin.H{"error": "photo_format"})
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, photos.MaxBytes))
	if err != nil {
		c.JSON(413, gin.H{"error": "photo_size"})
		return
	}
	subject := platform.Principal(c).Subject
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	receipt, err := s.photoUploads.Upload(ctx, subject, requestID, raw, media)
	if err != nil {
		writePhotoSourceFailure(c, receipt, err)
		return
	}
	c.JSON(202, receipt)
}

func (s *Server) confirmPhotoSource(c *gin.Context) {
	if !s.sourceAPIAvailable(c) {
		return
	}
	// Confirmation consumes no public payload; do not accept hidden alternate
	// commands or unbounded bodies on a storage read/retry route.
	if c.Request.ContentLength != 0 || c.Request.TransferEncoding != nil {
		c.JSON(400, gin.H{"error": "unexpected_body"})
		return
	}
	select {
	case s.photoUploadSlots <- struct{}{}:
		defer func() { <-s.photoUploadSlots }()
	default:
		c.JSON(429, gin.H{"error": "photo_upload_busy"})
		return
	}
	subject := platform.Principal(c).Subject
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	receipt, err := s.photoUploads.Confirm(ctx, subject, c.Param("id"))
	if err != nil {
		writePhotoSourceFailure(c, receipt, err)
		return
	}
	c.JSON(202, receipt)
}

func (s *Server) ownPhotoSource(c *gin.Context) {
	if !s.sourceAPIAvailable(c) {
		return
	}
	result, err := s.photoUploads.Status(c.Request.Context(), platform.Principal(c).Subject, c.Param("id"))
	if err != nil {
		writePhotoSourceFailure(c, photoassets.UploadStatus{}, err)
		return
	}
	c.JSON(200, result)
}

func (s *Server) ownPhotoUploadRequest(c *gin.Context) {
	if !s.sourceAPIAvailable(c) {
		return
	}
	result, err := s.photoUploads.RequestStatus(c.Request.Context(), platform.Principal(c).Subject, c.Param("id"))
	if err != nil {
		writePhotoSourceFailure(c, photoassets.UploadStatus{}, err)
		return
	}
	c.JSON(200, result)
}
