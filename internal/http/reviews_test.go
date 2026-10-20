package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/platform"
)

func TestVerifiedReviews(t *testing.T) {
	dsn := os.Getenv("RAC_ONBOARDING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated database")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ids := make([]string, 3)
	for i := range ids {
		if err = db.QueryRow(`INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) SELECT id,'Review fixture',id::text||'@fixture.test','cliente',id::text FROM (SELECT gen_random_uuid() id) v RETURNING id::text`).Scan(&ids[i]); err != nil {
			t.Fatal(err)
		}
	}
	defer db.Exec(`DELETE FROM usuario WHERE id IN ($1,$2,$3)`, ids[0], ids[1], ids[2])
	if _, err = db.Exec(`INSERT INTO compa_perfil(id,usuario_id,descripcion,tarifa_hora) VALUES(gen_random_uuid(),$1,'Review provider',1000)`, ids[1]); err != nil {
		t.Fatal(err)
	}
	var bookings []string
	defer func() {
		for _, id := range bookings {
			db.Exec(`DELETE FROM sesion WHERE id=$1`, id)
		}
	}()
	booking := func(state string, future bool) string {
		var id string
		offset := fmt.Sprintf("-%d hours", 3+len(bookings)*2)
		if future {
			offset = fmt.Sprintf("%d hours", 3+len(bookings)*2)
		}
		if err := db.QueryRow(`INSERT INTO sesion(id,cliente_id,compa_id,fecha_inicio,fecha_fin,estado) VALUES(gen_random_uuid(),$1,$2,now()+$4::interval,now()+$4::interval+interval '1 hour',$3) RETURNING id::text`, ids[0], ids[1], state, offset).Scan(&id); err != nil {
			t.Fatal(err)
		}
		bookings = append(bookings, id)
		return id
	}
	server := New(db, config.Config{})
	server.security = &platform.Security{VerifyToken: func(ctx context.Context, token string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: ids[0]}
		if token == "provider" {
			p.Subject = ids[1]
		}
		if token == "stranger" {
			p.Subject = ids[2]
		}
		p.RealmAccess.Roles = []string{"cliente"}
		return p, nil
	}}
	router := server.Router()
	request := func(method, path, token, body string, status int) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("%s %s status=%d expected=%d %s", method, path, w.Code, status, w.Body.String())
		}
		return w
	}
	finished := booking("finalizada", false)
	path := "/api/user/bookings/" + finished + "/review"
	request("POST", path, "", `{"puntuacion":5}`, 401)
	request("POST", path, "provider", `{"puntuacion":5}`, 404)
	request("POST", path, "stranger", `{"puntuacion":5}`, 404)
	request("GET", path, "stranger", "", 404)
	request("GET", path, "client", "", 200)
	for _, body := range []string{`{"puntuacion":0}`, `{"puntuacion":6}`, `{"puntuacion":3.5}`, `{"puntuacion":5,"cliente_id":"forged"}`, `{"puntuacion":5} {}`, `{"puntuacion":5,"comentario":"` + strings.Repeat("x", 1001) + `"}`} {
		request("POST", path, "client", body, 400)
	}
	for _, state := range []string{"pendiente", "activa", "cancelada"} {
		request("POST", "/api/user/bookings/"+booking(state, false)+"/review", "client", `{"puntuacion":5}`, 409)
	}
	request("POST", "/api/user/bookings/"+booking("finalizada", true)+"/review", "client", `{"puntuacion":5}`, 409)
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", path, strings.NewReader(`{"puntuacion":5,"comentario":"Gran experiencia"}`))
			req.Header.Set("Authorization", "Bearer client")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			statuses <- w.Code
		}()
	}
	wg.Wait()
	close(statuses)
	created, retried := 0, 0
	for status := range statuses {
		if status == 201 {
			created++
		} else if status == 200 {
			retried++
		} else {
			t.Fatal("concurrent review failed", status)
		}
	}
	if created != 1 || retried != 1 {
		t.Fatal("duplicate review", created, retried)
	}
	request("POST", path, "client", `{"puntuacion":1}`, 409)
	request("GET", path, "provider", "", 200)
	second := booking("finalizada", false)
	request("POST", "/api/user/bookings/"+second+"/review", "client", `{"puntuacion":1,"comentario":""}`, 201)
	response := request("GET", "/api/user/compas/"+ids[1], "", "", 200)
	var card map[string]any
	if err = json.Unmarshal(response.Body.Bytes(), &card); err != nil {
		t.Fatal(err)
	}
	if card["rating_promedio"] != float64(3) || card["cantidad_resenas"] != float64(2) {
		t.Fatal("average/count incorrect", card)
	}
	public := request("GET", "/api/user/compas/"+ids[1]+"/reviews", "", "", 200).Body.String()
	for _, secret := range []string{ids[0], ids[1], finished, "correo", "telefono", "cliente_id", "sesion_id"} {
		if strings.Contains(public, secret) {
			t.Fatal("public review leaks private data", secret)
		}
	}
	request("GET", "/api/user/compas/"+ids[1]+"/reviews?offset=-1", "", "", 400)
	pending := booking("pendiente", false)
	if _, err = db.Exec(`INSERT INTO reserva_resena(sesion_id,cliente_id,compa_id,puntuacion) VALUES($1,$2,$3,5)`, pending, ids[0], ids[1]); err == nil {
		t.Fatal("database accepted unverified review")
	}
}
