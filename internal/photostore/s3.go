package photostore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

type S3 struct {
	client     *s3.Client
	bucket     string
	keyPattern *regexp.Regexp
	mediaType  string
}

func FromEnvironment() (Store, error) {
	switch os.Getenv("PROFILE_PHOTO_STORAGE") {
	case "", "local":
		dir := os.Getenv("PROFILE_PHOTO_DIR")
		if dir == "" {
			dir = "/var/lib/rac/photos"
		}
		return Local{Directory: dir}, nil
	case "s3":
		return NewS3(os.Getenv("PROFILE_S3_ENDPOINT"), os.Getenv("PROFILE_S3_REGION"), os.Getenv("PROFILE_S3_BUCKET"), os.Getenv("PROFILE_S3_ACCESS_KEY"), os.Getenv("PROFILE_S3_SECRET_KEY"))
	default:
		return nil, errors.New("invalid profile storage driver")
	}
}
func NewS3(endpoint, region, bucket, access, secret string) (*S3, error) {
	return newS3(endpoint, region, bucket, access, secret, validKey, "image/jpeg")
}

func newS3(endpoint, region, bucket, access, secret string, keyPattern *regexp.Regexp, mediaType string) (*S3, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || region == "" || bucket == "" || access == "" || secret == "" {
		return nil, errors.New("incomplete or invalid profile S3 configuration")
	}
	client := s3.New(s3.Options{
		Region: region, BaseEndpoint: aws.String(endpoint), UsePathStyle: true,
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(access, secret, "")),
		HTTPClient:  &http.Client{Timeout: 8 * time.Second}, RetryMaxAttempts: 2,
	})
	return &S3{client: client, bucket: bucket, keyPattern: keyPattern, mediaType: mediaType}, nil
}
func (s *S3) Put(ctx context.Context, key string, data []byte) error {
	_, err := s.create(ctx, key, data)
	return err
}

func (s *S3) create(ctx context.Context, key string, data []byte) (string, error) {
	if !s.keyPattern.MatchString(key) || len(data) > MaxStoredBytes {
		return "", errors.New("invalid photo")
	}
	// A HEAD-before-PUT check has a race. Let the object store enforce creation
	// atomically, matching the local driver's O_EXCL contract.
	result, err := s.client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key), Body: bytes.NewReader(data), ContentType: aws.String(s.mediaType), CacheControl: aws.String("no-store"), IfNoneMatch: aws.String("*")})
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "PreconditionFailed":
			return "", ErrExists
		case "ConditionalRequestConflict":
			return "", ErrConflict
		}
	}
	if err != nil {
		return "", err
	}
	return aws.ToString(result.VersionId), nil
}
func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	raw, _, err := s.read(ctx, key, nil)
	return raw, err
}

func (s *S3) read(ctx context.Context, key string, version *string) ([]byte, string, error) {
	if !s.keyPattern.MatchString(key) {
		return nil, "", ErrNotFound
	}
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key), VersionId: version})
	if err != nil {
		var api smithy.APIError
		if errors.As(err, &api) && (api.ErrorCode() == "NoSuchKey" || api.ErrorCode() == "NotFound") {
			return nil, "", ErrNotFound
		}
		return nil, "", err
	}
	defer result.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(result.Body, MaxStoredBytes+1))
	if len(raw) > MaxStoredBytes {
		return nil, "", errors.New("stored photo exceeds limit")
	}
	return raw, aws.ToString(result.VersionId), err
}
func (s *S3) Delete(ctx context.Context, key string) error {
	if !s.keyPattern.MatchString(key) {
		return errors.New("invalid photo key")
	}
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	return err
}
func (s *S3) Check(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.bucket)})
	return err
}
