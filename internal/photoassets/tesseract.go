package photoassets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image/jpeg"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cazocarma/rac-platform/contentsignals"
	"github.com/cazocarma/rac-user-service/internal/photos"
)

// Tesseract is a local process adapter. It receives sanitized JPEG bytes over
// stdin; user filenames/arguments, cloud providers and stderr logs are absent.
type Tesseract struct{ binary, directory, version, models, executableSHA string }

type boundedOutput struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (w *boundedOutput) Write(raw []byte) (int, error) {
	if len(raw) > w.limit-w.Len() {
		w.overflow = true
		return 0, ErrProcessing
	}
	return w.Buffer.Write(raw)
}

func localCommand(ctx context.Context, path string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "OMP_THREAD_LIMIT=1", "HOME=/nonexistent"}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 500 * time.Millisecond
	return cmd
}

func NewTesseract(ctx context.Context, binary, directory string) (*Tesseract, error) {
	if !filepath.IsAbs(binary) || !filepath.IsAbs(directory) {
		return nil, ErrInvalid
	}
	before, err := fileDigest(binary)
	if err != nil {
		return nil, ErrProcessing
	}
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	output := &boundedOutput{limit: 8192}
	cmd := localCommand(probe, binary, "--version")
	cmd.Stdout = output
	if err := cmd.Run(); err != nil || output.overflow {
		return nil, ErrProcessing
	}
	version := strings.TrimSpace(strings.SplitN(output.String(), "\n", 2)[0])
	if !strings.HasPrefix(version, "tesseract ") || !ocrLabel(version) {
		return nil, ErrProcessing
	}
	// Pin the trained data actually passed via --tessdata-dir. The container's
	// dependency/SBOM proof remains separate; a version string is not its digest.
	models, err := modelDigest(directory)
	if err != nil {
		return nil, ErrProcessing
	}
	executableSHA, err := fileDigest(binary)
	if err != nil || executableSHA != before {
		return nil, ErrProcessing
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &Tesseract{binary: binary, directory: directory, version: version, models: models, executableSHA: executableSHA}, nil
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", ErrProcessing
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() < 1 || stat.Size() > 32*1024*1024 {
		return "", ErrProcessing
	}
	raw, err := io.ReadAll(io.LimitReader(file, 32*1024*1024+1))
	if err != nil || len(raw) > 32*1024*1024 {
		return "", ErrProcessing
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}
func modelDigest(directory string) (string, error) {
	models := map[string]string{}
	for _, language := range []string{"spa", "eng"} {
		hash, err := fileDigest(filepath.Join(directory, language+".traineddata"))
		if err != nil {
			return "", err
		}
		models[language] = hash
	}
	encoded, _ := json.Marshal(models)
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:]), nil
}
func (t *Tesseract) unchanged() bool {
	models, err := modelDigest(t.directory)
	if err != nil || models != t.models {
		return false
	}
	binary, err := fileDigest(t.binary)
	return err == nil && binary == t.executableSHA
}

func (t *Tesseract) Extract(ctx context.Context, raw []byte) (OCRResult, error) {
	if err := ctx.Err(); err != nil {
		return OCRResult{}, err
	}
	if !t.unchanged() {
		return OCRResult{}, ErrProcessing
	}
	if len(raw) < 1 || len(raw) > photos.MaxBytes {
		return OCRResult{}, ErrInvalid
	}
	dimensions, err := jpeg.DecodeConfig(bytes.NewReader(raw))
	if err != nil || dimensions.Width < 1 || dimensions.Height < 1 || dimensions.Width > 2048 || dimensions.Height > 2048 {
		return OCRResult{}, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	output := &boundedOutput{limit: contentsignals.MaxInput}
	cmd := localCommand(bounded, t.binary, "stdin", "stdout", "--tessdata-dir", t.directory, "-l", "spa+eng", "--psm", "11")
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Stdout = output
	err = cmd.Run()
	if bounded.Err() != nil {
		return OCRResult{}, bounded.Err()
	}
	if err != nil || output.overflow {
		return OCRResult{}, ErrProcessing
	}
	if t.version == "" || t.models == "" || !t.unchanged() {
		return OCRResult{}, ErrProcessing
	}
	return OCRResult{Text: output.String(), Version: t.version, ModelSHA256: t.models, ExecutableSHA256: t.executableSHA}, nil
}
