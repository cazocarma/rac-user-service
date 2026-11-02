package photostore

import (
	"context"
	"regexp"
)

// Quarantine stores untrusted originals as opaque private inputs, never JPEGs
// ready to serve. It has no Delete/presign/public-URL API. Bucket credentials
// still require separate least-privilege IAM provisioning before activation.
type Quarantine struct{ store *S3 }

func NewQuarantineS3(endpoint, region, bucket, access, secret string) (*Quarantine, error) {
	store, err := newS3(endpoint, region, bucket, access, secret, regexp.MustCompile(`^[a-f0-9]{32}\.raw$`), "application/octet-stream")
	if err != nil {
		return nil, err
	}
	return &Quarantine{store: store}, nil
}
func (q *Quarantine) Put(ctx context.Context, key string, raw []byte) error {
	return q.store.Put(ctx, key, raw)
}
func (q *Quarantine) Get(ctx context.Context, key string) ([]byte, error) {
	return q.store.Get(ctx, key)
}
func (q *Quarantine) Check(ctx context.Context) error { return q.store.Check(ctx) }
