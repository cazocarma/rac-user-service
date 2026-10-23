package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func validCompaProfile() compaProfile {
	return compaProfile{Description: "Compartamos actividades entretenidas juntos", Rate: 10000, Skills: []string{" Running ", "cine", "running"}, Availability: map[string][]string{"lunes": {"18:00-22:00"}}}
}

func TestCompaProfileValidation(t *testing.T) {
	profile := validCompaProfile()
	if err := profile.validate(); err != nil || len(profile.Skills) != 2 || profile.Skills[1] != "running" {
		t.Fatalf("normalize: %+v %v", profile, err)
	}
	for _, change := range []func(*compaProfile){
		func(p *compaProfile) { p.TimeZone = "Local" },
		func(p *compaProfile) { p.TimeZone = "not/a-zone" },
		func(p *compaProfile) { p.Rate = -1 },
		func(p *compaProfile) { p.Rate = 1.234 },
		func(p *compaProfile) { p.Description = "muy breve" },
		func(p *compaProfile) { p.Skills = []string{} },
		func(p *compaProfile) { p.Availability = map[string][]string{} },
		func(p *compaProfile) { p.Availability = map[string][]string{"monday": {"18:00-22:00"}} },
		func(p *compaProfile) { p.Availability = map[string][]string{"lunes": {"18:00-22:00", "21:00-23:00"}} },
		func(p *compaProfile) { p.Availability = map[string][]string{"lunes": {"24:00-25:00"}} },
		func(p *compaProfile) { p.Availability = map[string][]string{"lunes": {"22:00-18:00"}} },
	} {
		profile := validCompaProfile()
		change(&profile)
		if profile.validate() == nil {
			t.Fatalf("invalid profile accepted %+v", profile)
		}
	}
}

func TestCompaOnboardingTransaction(t *testing.T) {
	dsn := os.Getenv("RAC_ONBOARDING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable migrated database")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var sub, userID string
	if err = db.QueryRow(`SELECT gen_random_uuid()::text`).Scan(&sub); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`INSERT INTO usuario(id,nombre,correo,rol,keycloak_id) VALUES(gen_random_uuid(),'Onboarding',$1,'cliente',$2) RETURNING id::text`, sub+"@fixture.test", sub).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	skill := "fixture-" + sub[:24]
	defer func() {
		db.Exec(`DELETE FROM compa_availability WHERE compa_id=$1`, userID)
		db.Exec(`DELETE FROM usuario WHERE id=$1`, userID)
		db.Exec(`DELETE FROM skill WHERE name=$1`, skill)
	}()
	// Fixtures and cleanup use the disposable database owner. The HTTP handler
	// must run with the same limited privileges as backend-user in Compose.
	connection, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	options := connection.Query()
	options.Set("options", "-c role=rac_user")
	connection.RawQuery = options.Encode()
	serviceDB, err := sql.Open("postgres", connection.String())
	if err != nil {
		t.Fatal(err)
	}
	defer serviceDB.Close()
	var role string
	if err := serviceDB.QueryRow(`SELECT current_user`).Scan(&role); err != nil || role != "rac_user" {
		t.Fatalf("scoped service connection unavailable: %s %v", role, err)
	}
	s := New(serviceDB, config.Config{})
	roles := []string{"cliente"}
	s.security = &platform.Security{VerifyToken: func(context.Context, string) (*platform.Claims, error) {
		p := &platform.Claims{Subject: sub}
		p.RealmAccess.Roles = roles
		return p, nil
	}}
	calls := 0
	fail := true
	s.grantCompa = func(ctx context.Context, subject string) error {
		calls++
		if subject != sub {
			t.Error("foreign subject used")
		}
		if fail {
			return errors.New("offline")
		}
		return nil
	}
	router := s.Router()
	send := func(method, body string, expected int) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/user/me/compa", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer fixture")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != expected {
			t.Fatalf("%s %d: %s", method, w.Code, w.Body.String())
		}
		return w
	}
	p := validCompaProfile()
	p.Skills = []string{skill}
	raw, _ := json.Marshal(p)
	send("PUT", strings.TrimSuffix(string(raw), "}")+`,"role":"admin"}`, 400)
	if calls != 0 {
		t.Fatal("unknown fields reached provisioner")
	}
	send("PUT", string(raw), 503)
	if calls != 1 {
		t.Fatal("onboarding failed before reaching provisioner with scoped DB role")
	}
	send("GET", "", 404)
	var count int
	db.QueryRow(`SELECT count(*) FROM compa_availability WHERE compa_id=$1`, userID).Scan(&count)
	if count != 0 {
		t.Fatal("failed provisioning leaked availability")
	}
	fail = false
	send("PUT", string(raw), 200)
	send("PUT", string(raw), 200)
	w := send("GET", "", 200)
	if !strings.Contains(w.Body.String(), skill) {
		t.Fatal("profile skills not saved")
	}
	db.QueryRow(`SELECT count(*) FROM compa_perfil WHERE usuario_id=$1`, userID).Scan(&count)
	if count != 1 {
		t.Fatal("retry duplicated profile")
	}
	if calls != 3 {
		t.Fatal("unexpected provisioning calls", calls)
	}
	// The same already-issued identity must obey current standing, without
	// losing authenticated access to its own profile.
	t.Setenv("STANDING_ENFORCEMENT_ENABLED", "true")
	setStanding := func(status string) {
		t.Helper()
		if _, err := db.Exec(`UPDATE standing.account SET status=$2,version=version+1 WHERE subject_id=$1`, userID, status); err != nil {
			t.Fatal(err)
		}
	}
	setStanding("suspended")
	standingRequest := httptest.NewRequest("GET", "/api/user/me/standing", nil)
	standingRequest.Header.Set("Authorization", "Bearer fixture")
	standingResponse := httptest.NewRecorder()
	router.ServeHTTP(standingResponse, standingRequest)
	var view struct {
		Status       string          `json:"status"`
		Capabilities map[string]bool `json:"capabilities"`
	}
	if err := json.Unmarshal(standingResponse.Body.Bytes(), &view); err != nil || standingResponse.Code != 200 || view.Status != "suspended" {
		t.Fatal("own standing unavailable", standingResponse.Body.String(), err)
	}
	if view.Capabilities["publish_listing"] || !view.Capabilities["access_safety"] || !view.Capabilities["request_privacy"] || !view.Capabilities["cancel_own_booking"] {
		t.Fatal("incorrect commercial/protective capabilities", view)
	}

	send("PUT", string(raw), 403)
	send("GET", "", 200)
	if calls != 3 {
		t.Fatal("restricted request reached identity provisioner")
	}
	setStanding("active")
	send("PUT", string(raw), 200)
	// Change authority after profile writes, while the transaction is still
	// open. The final version check must roll back all local changes.
	p.Description = "Este cambio concurrente no debe quedar publicado"
	changed, _ := json.Marshal(p)
	s.grantCompa = func(context.Context, string) error {
		setStanding("banned")
		return nil
	}
	send("PUT", string(changed), 403)
	var description string
	if err := db.QueryRow(`SELECT descripcion FROM compa_perfil WHERE usuario_id=$1`, userID).Scan(&description); err != nil {
		t.Fatal(err)
	}
	if description != validCompaProfile().Description {
		t.Fatal("standing race committed profile changes", description)
	}
	send("GET", "", 200)

	// The older aliases must not bypass the same authority by using the compa
	// role from an otherwise valid token.
	roles = []string{"cliente", "compa"}
	var profileID string
	if err := db.QueryRow(`SELECT id::text FROM compa_perfil WHERE usuario_id=$1`, userID).Scan(&profileID); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []struct{ path, body string }{
		{"/api/user/compas", `{"descripcion":"Legacy bypass attempt","tarifa_hora":1}`},
		{"/api/user/compas/" + profileID + "/skills", `{"skills":["bypass"]}`},
	} {
		req := httptest.NewRequest("POST", endpoint.path, strings.NewReader(endpoint.body))
		req.Header.Set("Authorization", "Bearer fixture")
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		if response.Code != 403 {
			t.Fatal("legacy alias bypassed standing", endpoint.path, response.Code, response.Body.String())
		}
	}

	// Public visibility is filtered in SQL before pagination. Owners can still
	// read their private profile and retained photo through authenticated routes.
	assertVisible := func(want bool) {
		t.Helper()
		cards, err := s.repo.ListCompas(context.Background(), 1, 0, skill, true)
		if err != nil || (len(cards) == 1) != want {
			t.Fatal("catalog standing mismatch", len(cards), want, err)
		}
		for _, endpoint := range []string{"/api/user/compas/" + userID, "/api/user/compas/" + userID + "/reviews"} {
			req := httptest.NewRequest("GET", endpoint, nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			wantStatus := 404
			if want {
				wantStatus = 200
			}
			if response.Code != wantStatus {
				t.Fatal("public visibility mismatch", endpoint, response.Code, response.Body.String())
			}
		}
	}
	assertVisible(false)
	setStanding("active")
	assertVisible(true)
	if _, err := db.Exec(`INSERT INTO standing.restriction(subject_id,capability,starts_at,ends_at) VALUES($1,'publish_listing',now()-interval '1 minute',now()+interval '1 minute')`, userID); err != nil {
		t.Fatal(err)
	}
	assertVisible(false)
	if _, err := db.Exec(`UPDATE standing.restriction SET ends_at=now()-interval '1 second' WHERE subject_id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	assertVisible(true)
	setStanding("banned")
	key := strings.Repeat("a", 32) + ".jpg"
	if _, err := db.Exec(`UPDATE usuario SET foto_clave=$2 WHERE id=$1`, userID, key); err != nil {
		t.Fatal(err)
	}
	photo := httptest.NewRecorder()
	router.ServeHTTP(photo, httptest.NewRequest("GET", "/api/user/media/profile/"+key, nil))
	if photo.Code != 404 {
		t.Fatal("banned photo remains public", photo.Code)
	}

}
