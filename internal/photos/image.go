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

func Normalize(raw []byte, mediaType string) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxBytes {
		return nil, errors.New("photo_size")
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(raw))
	expected := map[string]string{"image/jpeg": "jpeg", "image/png": "png"}[mediaType]
	if err != nil || expected == "" || format != expected {
		return nil, errors.New("photo_format")
	}
	// Validate dimensions before allocating decoded pixels (decompression bombs).
	if config.Width < 32 || config.Height < 32 || config.Width > 4096 || config.Height > 4096 || int64(config.Width)*int64(config.Height) > 12000000 {
		return nil, errors.New("photo_dimensions")
	}
	img, err := imaging.Decode(bytes.NewReader(raw), imaging.AutoOrientation(true))
	if err != nil {
		return nil, errors.New("photo_decode")
	}
	square := imaging.Fill(img, 512, 512, imaging.Center, imaging.Lanczos)
	// Flatten alpha against white, normalize orientation, and strip EXIF/GPS and
	// trailing content by encoding a completely new JPEG.
	output := image.NewRGBA(square.Bounds())
	draw.Draw(output, output.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	draw.Draw(output, output.Bounds(), square, square.Bounds().Min, draw.Over)
	var buf bytes.Buffer
	if err = jpeg.Encode(&buf, output, &jpeg.Options{Quality: 85}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
