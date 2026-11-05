package listingreview

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	"github.com/cazocarma/rac-user-service/internal/photostore"
	"github.com/cazocarma/rac-user-service/internal/secretfile"
)

type photoApprovalRuntime struct {
	databaseURL string
	policy      promotionPolicy
	source      PreviewStore
	destination promotionDestination
}

func photoApprovalEnvironment(approval ApprovalPolicy) (*photoApprovalRuntime, error) {
	fail := errors.New("invalid private photo approval configuration")
	switch os.Getenv("RAC_PHOTO_PROMOTION_ENABLED") {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, fail
	}
	if os.Getenv("RAC_ENV") != "dev" || os.Getenv("RAC_PHOTO_PREVIEW_ENABLED") != "true" {
		return nil, fail
	}
	if preview, err := photoPreviewFromEnvironment(); err != nil || preview == nil {
		return nil, fail
	}
	staging, quarantine, media := os.Getenv("RAC_PHOTO_STAGING_BUCKET"), os.Getenv("RAC_PHOTO_QUARANTINE_BUCKET"), os.Getenv("RAC_PHOTO_MEDIA_BUCKET")
	if staging == "" || quarantine == "" || media == "" || staging == quarantine || staging == media || quarantine == media {
		return nil, fail
	}
	if profile := os.Getenv("PROFILE_S3_BUCKET"); profile != "" && (profile == staging || profile == quarantine || profile == media) {
		return nil, fail
	}
	dsn := os.Getenv("LISTING_REVIEW_PHOTO_APPROVER_DATABASE_URL")
	if dsn == "" {
		return nil, fail
	}
	for _, name := range []string{"LISTING_REVIEW_READER_DATABASE_URL", "LISTING_REVIEW_CORRECTOR_DATABASE_URL", "LISTING_REVIEW_APPROVER_DATABASE_URL"} {
		if dsn == os.Getenv(name) {
			return nil, fail
		}
	}
	access, err := secretfile.ReadEnvironment("RAC_PHOTO_PROMOTER_ACCESS_KEY")
	if err != nil {
		return nil, fail
	}
	secret, err := secretfile.ReadEnvironment("RAC_PHOTO_PROMOTER_SECRET_KEY")
	if err != nil {
		return nil, fail
	}
	for _, key := range []string{"PROFILE_S3_ACCESS_KEY", "AWS_ACCESS_KEY_ID"} {
		if access == os.Getenv(key) {
			return nil, fail
		}
	}
	for _, key := range []string{"PROFILE_S3_SECRET_KEY", "AWS_SECRET_ACCESS_KEY"} {
		if secret == os.Getenv(key) {
			return nil, fail
		}
	}
	for _, identity := range []string{"INGEST", "QUARANTINE", "STAGING", "PREVIEW"} {
		for _, part := range []string{"ACCESS_KEY", "SECRET_KEY"} {
			name := "RAC_PHOTO_" + identity + "_" + part
			if os.Getenv(name+"_FILE") != "" {
				value, err := secretfile.ReadEnvironment(name)
				if err != nil || (part == "ACCESS_KEY" && access == value) || (part == "SECRET_KEY" && secret == value) {
					return nil, fail
				}
			}
		}
	}
	endpoint, region := os.Getenv("RAC_PHOTO_S3_ENDPOINT"), os.Getenv("RAC_PHOTO_S3_REGION")
	locator := sha256.Sum256([]byte(strings.TrimRight(endpoint, "/")))
	policy := promotionPolicy{Listing: approval.ListingPolicy, Pipeline: os.Getenv("RAC_PHOTO_PIPELINE_VERSION"), Target: os.Getenv("RAC_PHOTO_MEDIA_TARGET_ID"),
		Bucket: media, Region: region, LocatorSHA256: hex.EncodeToString(locator[:])}
	if !policy.valid() {
		return nil, fail
	}
	source, err := photostore.NewS3Reader(endpoint, region, staging, access, secret)
	if err != nil {
		return nil, fail
	}
	destination, err := photostore.NewVersionedS3(endpoint, region, media, access, secret)
	if err != nil {
		return nil, fail
	}
	return &photoApprovalRuntime{databaseURL: dsn, policy: policy, source: source, destination: destination}, nil
}
