package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// CompaProvisioner can only grant the fixed compa role to an authenticated subject.
// Master-admin credentials are never available in this service.
var roleIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type CompaProvisioner struct {
	RoleIDFile string
	Base       string
	Secret     string
	Client     *http.Client
}

func NewCompaProvisioner() *CompaProvisioner {
	return &CompaProvisioner{RoleIDFile: os.Getenv("COMPA_ROLE_ID_FILE"), Base: strings.TrimRight(os.Getenv("KEYCLOAK_INTERNAL_URL"), "/"), Secret: os.Getenv("COMPA_PROVISIONER_SECRET"), Client: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (p *CompaProvisioner) Grant(ctx context.Context, subject string) error {
	if p.Base == "" || p.Secret == "" || subject == "" {
		return errors.New("compa provisioning unavailable")
	}
	file, err := os.Open(p.RoleIDFile)
	if err != nil {
		return errors.New("compa role configuration unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 129))
	file.Close()
	roleID := strings.TrimSpace(string(raw))
	if err != nil || len(raw) > 128 || !roleIDPattern.MatchString(roleID) || roleID == "00000000-0000-0000-0000-000000000000" {
		return errors.New("invalid compa role configuration")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"rac-compa-provisioner"}, "client_secret": {p.Secret}}
	req, err := http.NewRequestWithContext(ctx, "POST", p.Base+"/realms/rentacompa/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("invalid identity configuration")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := p.Client.Do(req)
	if err != nil {
		return errors.New("identity unavailable")
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&token)
	res.Body.Close()
	if res.StatusCode != 200 || err != nil || token.AccessToken == "" {
		return errors.New("identity authentication failed")
	}
	admin := p.Base + "/admin/realms/rentacompa"
	role := struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}{ID: roleID, Name: "compa"}
	body, _ := json.Marshal([]any{role})
	req, _ = http.NewRequestWithContext(ctx, "POST", admin+"/users/"+url.PathEscape(subject)+"/role-mappings/realm", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	res, err = p.Client.Do(req)
	if err != nil {
		return errors.New("identity unavailable")
	}
	res.Body.Close()
	if res.StatusCode != 204 {
		return errors.New("compa role assignment failed")
	}
	return nil
}
