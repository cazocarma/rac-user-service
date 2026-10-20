// Package photostore persists normalized profile photos without deciding publication.
package photostore

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var ErrNotFound = errors.New("photo not found")
var validKey = regexp.MustCompile(`^[a-f0-9]{32}\.jpg$`)

const MaxStoredBytes = 5 * 1024 * 1024

type Store interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
	Check(context.Context) error
}

type Local struct{ Directory string }

func (l Local) Check(context.Context) error { _, err := os.Stat(l.Directory); return err }
func (l Local) Put(ctx context.Context, key string, data []byte) error {
	if !validKey.MatchString(key) || len(data) > MaxStoredBytes {
		return errors.New("invalid photo")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(l.Directory, 0700); err != nil {
		return err
	}
	path := filepath.Join(l.Directory, key)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(path)
	}
	return err
}
func (l Local) Get(ctx context.Context, key string) ([]byte, error) {
	if !validKey.MatchString(key) {
		return nil, ErrNotFound
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(l.Directory, key))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxStoredBytes+1))
	if len(data) > MaxStoredBytes {
		return nil, errors.New("stored photo exceeds limit")
	}
	return data, err
}
func (l Local) Delete(ctx context.Context, key string) error {
	if !validKey.MatchString(key) {
		return errors.New("invalid photo key")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(l.Directory, key))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
