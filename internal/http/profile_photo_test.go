package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/cazocarma/rac-user-service/internal/photostore"
	"github.com/gin-gonic/gin"
	"image"
	"image/png"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/platform"
)

type failingPhotoStore struct{ photostore.Store }

func (f failingPhotoStore) Put(context.Context, string, []byte) error {
	return errors.New("injected unavailable storage")
}

func TestProfilePhotosOwnershipAndPublication(t *testing.T) {
	t.Run("local", func(t *testing.T) { testProfilePhotos(t, false) })
	if os.Getenv("RAC_PHOTO_TEST_S3_ENDPOINT") != "" {
		t.Run("s3", func(t *testing.T) { testProfilePhotos(t, true) })
	}
}
func testProfilePhotos(t *testing.T, useS3 bool) {
	dsn := os.Getenv("RAC_ONBOARDING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated database")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var sub, id, other string
	if err = db.QueryRow(`SELECT gen_random_uuid()::text,gen_random_uuid()::text`).Scan(&sub, &other); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) VALUES(gen_random_uuid(),'Photo',$1,'cliente',$2) RETURNING id::text`, sub+"@fixture.test", sub).Scan(&id); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`DELETE FROM usuario WHERE id=$1`, id)
	s := New(db, config.Config{})
	s.photoDir = t.TempDir()
	if useS3 {
		store, err := photostore.NewS3(os.Getenv("RAC_PHOTO_TEST_S3_ENDPOINT"), "us-east-1", os.Getenv("PROFILE_S3_BUCKET"), os.Getenv("PROFILE_S3_ACCESS_KEY"), os.Getenv("PROFILE_S3_SECRET_KEY"))
		if err != nil {
			t.Fatal(err)
		}
		s.photoStore = store
	}
	s.security = &platform.Security{VerifyToken: func(ctx context.Context, token string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: sub}
		if token == "other" {
			p.Subject = other
		}
		p.RealmAccess.Roles = []string{"cliente"}
		return p, nil
	}}
	router := s.Router()
	request := func(method, path, token, media string, body []byte, expected int) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", media)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != expected {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		return w
	}
	var imageBytes bytes.Buffer
	png.Encode(&imageBytes, image.NewRGBA(image.Rect(0, 0, 96, 96)))
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		request(method, "/api/user/me/photo", "", "image/png", imageBytes.Bytes(), 401)
	}
	request("PUT", "/api/user/me/photo", "own", "image/svg+xml", []byte("<svg/>"), 415)
	request("PUT", "/api/user/me/photo", "own", "image/png", []byte("invalid"), 400)
	request("PUT", "/api/user/me/photo", "other", "image/png", imageBytes.Bytes(), 409)
	response := request("PUT", "/api/user/me/photo", "own", "image/png", imageBytes.Bytes(), 200)
	var result map[string]string
	json.Unmarshal(response.Body.Bytes(), &result)
	key := result["foto_version"]
	if !photoKey.MatchString(key) {
		t.Fatal("unsafe generated key")
	}
	request("PUT", "/api/user/me/photo", "own", "image/png", []byte("broken replacement"), 400)
	originalStore := s.photoStore
	s.photoStore = failingPhotoStore{Store: s.photos()}
	request("PUT", "/api/user/me/photo", "own", "image/png", imageBytes.Bytes(), 503)
	s.photoStore = originalStore
	var preserved string
	if err = db.QueryRow(`SELECT foto_clave FROM usuario WHERE id=$1`, id).Scan(&preserved); err != nil || preserved != key {
		t.Fatal("failed replacement changed photo", err)
	}
	request("GET", "/api/user/me/photo", "other", "", nil, 404)
	own := request("GET", "/api/user/me/photo", "own", "", nil, 200)
	if own.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private photo can be cached")
	}
	publicPath := "/api/user/media/profile/" + key
	request("GET", publicPath, "", "", nil, 404)
	if _, err = db.Exec(`INSERT INTO compa_perfil(id,usuario_id,descripcion,tarifa_hora) VALUES(gen_random_uuid(),$1,'Published',1000)`, id); err != nil {
		t.Fatal(err)
	}
	request("GET", publicPath, "", "", nil, 200)
	card := request("GET", "/api/user/compas/"+id, "", "", nil, 200)
	if strings.Contains(card.Body.String(), "correo") || strings.Contains(card.Body.String(), "telefono") || !strings.Contains(card.Body.String(), publicPath) {
		t.Fatal("public profile privacy or photo URL incorrect", card.Body.String())
	}
	replacement := request("PUT", "/api/user/me/photo", "own", "image/png", imageBytes.Bytes(), 200)
	json.Unmarshal(replacement.Body.Bytes(), &result)
	if _, err = s.photos().Get(context.Background(), key); !errors.Is(err, photostore.ErrNotFound) {
		t.Fatal("old photo retained")
	}
	request("GET", publicPath, "", "", nil, 404)
	var uploads sync.WaitGroup
	responses := make(chan int, 2)
	for i := 0; i < 2; i++ {
		uploads.Add(1)
		go func() {
			defer uploads.Done()
			req := httptest.NewRequest("PUT", "/api/user/me/photo", bytes.NewReader(imageBytes.Bytes()))
			req.Header.Set("Authorization", "Bearer own")
			req.Header.Set("Content-Type", "image/png")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			responses <- w.Code
		}()
	}
	uploads.Wait()
	close(responses)
	for status := range responses {
		if status != 200 {
			t.Fatal("concurrent replacement failed", status)
		}
	}
	activeFiles, _ := os.ReadDir(s.photoDir)
	if !useS3 && len(activeFiles) != 1 {
		t.Fatal("concurrent replacement leaked photos", len(activeFiles))
	}
	if err = db.QueryRow(`SELECT foto_clave FROM usuario WHERE id=$1`, id).Scan(&preserved); err != nil {
		t.Fatal(err)
	}
	result["foto_version"] = preserved
	request("DELETE", "/api/user/me/photo", "other", "", nil, 409)
	request("DELETE", "/api/user/me/photo", "own", "", nil, 200)
	request("DELETE", "/api/user/me/photo", "own", "", nil, 200)
	request("GET", "/api/user/media/profile/"+result["foto_version"], "", "", nil, 404)
	files, _ := os.ReadDir(s.photoDir)
	if !useS3 && len(files) != 0 {
		t.Fatal("deleted photos remain on disk")
	}
}

type unreadablePhotoStore struct{ photostore.Store }

func (f unreadablePhotoStore) Get(context.Context, string) ([]byte, error) {
	return nil, errors.New("storage offline")
}
func (f unreadablePhotoStore) Check(context.Context) error { return errors.New("storage offline") }
func TestPhotoStorageUnavailableIs503(t *testing.T) {
	store := unreadablePhotoStore{}
	server := &Server{photoStore: store}
	r := gin.New()
	platform.Health(r, nil, store.Check)
	r.GET("/photo", func(c *gin.Context) { server.servePhoto(c, strings.Repeat("a", 32)+".jpg") })
	for _, path := range []string{"/photo", "/ready"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 503 {
			t.Fatal("storage outage hidden", path, w.Code)
		}
	}
}
