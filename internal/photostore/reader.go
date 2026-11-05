package photostore

import "context"

// S3Reader exposes only a bounded Get. The credential must independently be
// restricted by bucket IAM; a narrower Go interface does not grant isolation.
type S3Reader struct{ store *S3 }

func NewS3Reader(endpoint, region, bucket, access, secret string) (*S3Reader, error) {
	store, err := NewS3(endpoint, region, bucket, access, secret)
	if err != nil {
		return nil, err
	}
	return &S3Reader{store: store}, nil
}

func (r *S3Reader) Get(ctx context.Context, key string) ([]byte, error) {
	return r.store.Get(ctx, key)
}
