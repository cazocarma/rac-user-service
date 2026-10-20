package photos

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"
)

func TestNormalizeRejectsUnsafeAndOversizedImages(t *testing.T) {
	var small, wide bytes.Buffer
	png.Encode(&small, image.NewRGBA(image.Rect(0, 0, 64, 96)))
	png.Encode(&wide, image.NewRGBA(image.Rect(0, 0, 4097, 32)))
	for _, item := range []struct {
		raw  []byte
		mime string
	}{{[]byte(`<svg onload="alert(1)"/>`), "image/png"}, {small.Bytes(), "image/jpeg"}, {small.Bytes(), "image/gif"}, {wide.Bytes(), "image/png"}, {make([]byte, MaxBytes+1), "image/png"}, {small.Bytes()[:25], "image/png"}} {
		if _, err := Normalize(item.raw, item.mime); err == nil {
			t.Fatal("unsafe upload accepted", item.mime)
		}
	}
}

func TestNormalizeReencodesSquareWithoutOriginalPayload(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 640, 320))
	for y := 0; y < 320; y++ {
		for x := 0; x < 640; x++ {
			img.Set(x, y, color.RGBA{R: 150, G: 70, A: 255})
		}
	}
	var input bytes.Buffer
	png.Encode(&input, img)
	input.WriteString("original-private-GPS-marker")
	raw, err := Normalize(input.Bytes(), "image/png")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(raw))
	if err != nil || cfg.Width != 512 || cfg.Height != 512 {
		t.Fatal("unexpected output", cfg, err)
	}
	if bytes.Contains(raw, []byte("original-private-GPS-marker")) {
		t.Fatal("original payload retained")
	}
}
