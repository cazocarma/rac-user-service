package photoassets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"image"
	"image/png"
	"testing"
)

func sourceFixture(t *testing.T) Upload {
	t.Helper()
	var raw bytes.Buffer
	if err := png.Encode(&raw, image.NewRGBA(image.Rect(0, 0, 64, 48))); err != nil {
		t.Fatal(err)
	}
	upload, err := Prepare(context.Background(), raw.Bytes(), "image/png", "fixture-pipeline-1")
	if err != nil {
		t.Fatal(err)
	}
	return upload
}

type readerFunc func(context.Context, string) ([]byte, error)

func (f readerFunc) Get(ctx context.Context, key string) ([]byte, error) { return f(ctx, key) }

func TestPrivateSourcePreparationAndReadback(t *testing.T) {
	upload := sourceFixture(t)
	source := upload.Source()
	if source.Size() != len(upload.Bytes()) || source.Digest() != sha256.Sum256(upload.Bytes()) || len(source.ID()) != 36 || len(source.ObjectKey()) != 36 {
		t.Fatal("invalid source descriptor")
	}
	copy := upload.Bytes()
	copy[0] ^= 0xff
	if source.Digest() != sha256.Sum256(upload.Bytes()) {
		t.Fatal("caller mutated reserved source")
	}
	wrong := upload.Bytes()
	wrong[len(wrong)-1] ^= 0xff
	for _, data := range [][]byte{wrong, upload.Bytes()[:10]} {
		if _, err := Verify(context.Background(), readerFunc(func(context.Context, string) ([]byte, error) { return data, nil }), source); !errors.Is(err, ErrIntegrity) {
			t.Fatal("unverified object accepted", err)
		}
	}
	verified, err := Verify(context.Background(), readerFunc(func(_ context.Context, key string) ([]byte, error) {
		if key != source.ObjectKey() {
			t.Fatal("wrong private key")
		}
		return upload.Bytes(), nil
	}), source)
	if err != nil || verified.source != source {
		t.Fatal("readback did not verify exact descriptor", err)
	}
	if _, err := Prepare(context.Background(), upload.Bytes(), "image/jpeg", "fixture-pipeline-1"); !errors.Is(err, ErrInvalid) {
		t.Fatal("MIME assertion bypassed magic bytes")
	}
	if _, err := Prepare(context.Background(), []byte("not an image"), "image/png", "fixture-pipeline-1"); !errors.Is(err, ErrInvalid) {
		t.Fatal("non-image accepted")
	}
	if _, err := Prepare(context.Background(), upload.Bytes(), "image/png", ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("unversioned pipeline accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Prepare(ctx, upload.Bytes(), "image/png", "fixture-pipeline-1"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled preparation succeeded")
	}
	ctx, cancel = context.WithCancel(context.Background())
	if _, err := Verify(ctx, readerFunc(func(context.Context, string) ([]byte, error) { cancel(); return nil, context.Canceled }), source); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled readback confirmed", err)
	}
}
