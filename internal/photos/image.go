// Package photos normalizes untrusted uploads; original files are never served.
package photos

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	_ "image/png"

	"github.com/disintegration/imaging"
)

const MaxBytes = 5 * 1024 * 1024

// Metadata describes the source header, not a decoded, sanitized or approved
// photo. Originals remain private; Normalize must still decode and reencode.
type Metadata struct {
	Width, Height int
	MediaType     string
}

func Inspect(raw []byte, mediaType string) (Metadata, error) {
	if len(raw) == 0 || len(raw) > MaxBytes {
		return Metadata{}, errors.New("photo_size")
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(raw))
	expected := map[string]string{"image/jpeg": "jpeg", "image/png": "png"}[mediaType]
	if err != nil || expected == "" || format != expected {
		return Metadata{}, errors.New("photo_format")
	}
	// Validate dimensions before allocating decoded pixels (decompression bombs).
	if config.Width < 32 || config.Height < 32 || config.Width > 4096 || config.Height > 4096 || int64(config.Width)*int64(config.Height) > 12000000 {
		return Metadata{}, errors.New("photo_dimensions")
	}
	return Metadata{Width: config.Width, Height: config.Height, MediaType: mediaType}, nil
}

func Normalize(raw []byte, mediaType string) ([]byte, error) {
	return normalize(raw, mediaType, true)
}

// NormalizeFull preserves the entire oriented frame for OCR/review. Cropping
// before analysis could remove a contact written along an edge. Neither output
// constitutes publication approval; both are newly encoded without metadata.
func NormalizeFull(raw []byte, mediaType string) ([]byte, error) {
	return normalize(raw, mediaType, false)
}

func normalize(raw []byte, mediaType string, square bool) ([]byte, error) {
	if _, err := Inspect(raw, mediaType); err != nil {
		return nil, err
	}
	img, err := imaging.Decode(bytes.NewReader(raw), imaging.AutoOrientation(true))
	if err != nil {
		return nil, errors.New("photo_decode")
	}
	var resized image.Image
	if square {
		resized = imaging.Fill(img, 512, 512, imaging.Center, imaging.Lanczos)
	} else {
		resized = imaging.Fit(img, 2048, 2048, imaging.Lanczos)
	}
	// Flatten alpha against white, normalize orientation, and strip EXIF/GPS and
	// trailing content by encoding a completely new JPEG.
	output := image.NewRGBA(resized.Bounds())
	draw.Draw(output, output.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	draw.Draw(output, output.Bounds(), resized, resized.Bounds().Min, draw.Over)
	var buf bytes.Buffer
	if err = jpeg.Encode(&buf, output, &jpeg.Options{Quality: 85}); err != nil {
		return nil, err
	}
	if buf.Len() > MaxBytes {
		return nil, errors.New("photo_size")
	}
	return buf.Bytes(), nil
}
