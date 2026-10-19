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
	"strings"
	"time"
)

// CompaProvisioner can only grant the fixed compa role to a verified subject.
// Master-admin credentials are never available in this service.
type CompaProvisioner struct {
	Base   string
	Secret string
	Client *http.Client
}

func NewCompaProvisioner() *CompaProvisioner {
	return &CompaProvisioner{Base: strings.TrimRight(os.Getenv("KEYCLOAK_INTERNAL_URL"), "/"), Secret: os.Getenv("COMPA_PROVISIONER_SECRET"), Client: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (p *CompaProvisioner) Grant(ctx context.Context, subject string) error {
	if p.Base == "" || p.Secret == "" || subject == "" {
		return errors.New("compa provisioning unavailable")
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
	req, _ = http.NewRequestWithContext(ctx, "GET", admin+"/roles/compa", nil)
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	res, err = p.Client.Do(req)
	if err != nil {
		return errors.New("identity unavailable")
	}
	var role struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&role)
	res.Body.Close()
	if res.StatusCode != 200 || err != nil || role.ID == "" || role.Name != "compa" {
		return errors.New("compa role unavailable")
	}
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
