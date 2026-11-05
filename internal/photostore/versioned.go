package photostore

import (
	"context"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrVersionUnavailable = errors.New("photo object version unavailable")

// VersionID is opaque provider metadata, never an ETag, content digest or URL.
// Empty/null versions do not establish versioned storage. Keep technical input
// bounds without interpreting S3-specific opaque IDs as UUIDs.
func ValidVersionID(id string) bool {
	return id != "" && id != "null" && len(id) <= 2048 && utf8.ValidString(id) &&
		strings.TrimSpace(id) == id && strings.IndexFunc(id, unicode.IsControl) < 0
}

type VersionedObject struct {
	version string
	data    []byte
}

func (o VersionedObject) VersionID() string { return o.version }
func (o VersionedObject) Bytes() []byte     { return slices.Clone(o.data) }

// VersionedS3 is for private approved-media destinations, never quarantine,
// avatars or legal evidence. It deliberately exposes no delete/ACL/presign/list
// operation. IAM and explicit bucket versioning are independent requirements.
type VersionedS3 struct{ store *S3 }

func NewVersionedS3(endpoint, region, bucket, access, secret string) (*VersionedS3, error) {
	store, err := NewS3(endpoint, region, bucket, access, secret)
	if err != nil {
		return nil, err
	}
	return &VersionedS3{store: store}, nil
}

// Create is conditional. Even successful creation does not prove persisted
// content: the coordinator must read the returned version and check its bytes.
// On any error, retain the durable intent; an object may already exist.
func (s *VersionedS3) Create(ctx context.Context, key string, data []byte) (string, error) {
	id, err := s.store.create(ctx, key, data)
	if err != nil {
		return "", err
	}
	if !ValidVersionID(id) {
		return "", ErrVersionUnavailable
	}
	return id, nil
}

// Current supports recovery after an uncertain creation ACK, not publication
// by "latest". A recovered version must subsequently be read explicitly.
func (s *VersionedS3) Current(ctx context.Context, key string) (VersionedObject, error) {
	data, id, err := s.store.read(ctx, key, nil)
	if err != nil {
		return VersionedObject{}, err
	}
	if !ValidVersionID(id) {
		return VersionedObject{}, ErrVersionUnavailable
	}
	return VersionedObject{version: id, data: slices.Clone(data)}, nil
}

func (s *VersionedS3) Version(ctx context.Context, key, id string) ([]byte, error) {
	if !ValidVersionID(id) {
		return nil, ErrVersionUnavailable
	}
	data, actual, err := s.store.read(ctx, key, &id)
	if err != nil {
		return nil, err
	}
	if actual != id {
		return nil, ErrVersionUnavailable
	}
	return slices.Clone(data), nil
}
