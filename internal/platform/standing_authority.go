package platform

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	documentsdb "github.com/cazocarma/rac-platform/documents/postgres"
	documentstransport "github.com/cazocarma/rac-platform/documents/transport"
	standingdb "github.com/cazocarma/rac-platform/standing/postgres"
	"github.com/cazocarma/rac-platform/standing/transport"
)

// StandingAuthorityFromEnvironment builds a separate internal listener. The
// public router never registers this path. Rollout remains explicit until all
// commercial writers and reconciliation are covered.
func StandingAuthorityFromEnvironment(db *sql.DB) (*http.Server, error) {
	documentsEnabled := os.Getenv("DOCUMENTS_ENFORCEMENT_ENABLED")
	if documentsEnabled != "" && documentsEnabled != "false" && documentsEnabled != "true" {
		return nil, errors.New("invalid document rollout configuration")
	}
	if documentsEnabled == "true" && os.Getenv("STANDING_ENFORCEMENT_ENABLED") != "true" {
		return nil, errors.New("document authority requires standing infrastructure")
	}

	switch os.Getenv("STANDING_ENFORCEMENT_ENABLED") {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, errors.New("invalid standing rollout configuration")
	}
	file, err := os.Open(os.Getenv("STANDING_SUBJECTS_FILE"))
	if err != nil {
		return nil, errStandingReader
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil || len(data) > 16384 {
		return nil, errStandingReader
	}
	var subjects map[string]string
	d := json.NewDecoder(bytes.NewReader(data))
	if d.Decode(&subjects) != nil || d.Decode(new(any)) != io.EOF {
		return nil, errStandingReader
	}
	if len(subjects) != 3 {
		return nil, errStandingReader
	}
	seen := map[string]bool{}
	for _, client := range []string{"rac-match-standing", "rac-chat-standing", "rac-alert-standing"} {
		subject := subjects[client]
		if subject == "" || seen[subject] {
			return nil, errStandingReader
		}
		seen[subject] = true
	}
	keys := os.Getenv("STANDING_JWKS_URL")
	if keys == "" {
		keys = os.Getenv("OIDC_JWKS_URL")
	}
	readerConfig := StandingReaderConfig{
		Issuer: os.Getenv("OIDC_ISSUER"), JWKS: keys, Audience: "rac-standing",
		Subjects: map[string]string{"rac-match-standing": subjects["rac-match-standing"], "rac-chat-standing": subjects["rac-chat-standing"]}, AllowDevelopmentHTTP: os.Getenv("RAC_ENV") == "dev",
	}
	auth, err := NewStandingReader(readerConfig)
	if err != nil {
		return nil, err
	}
	// Chat can check its participants, but cannot crawl recovery history.
	readerConfig.Subjects = map[string]string{"rac-match-standing": subjects["rac-match-standing"], "rac-alert-standing": subjects["rac-alert-standing"]}
	replayAuth, err := NewStandingReader(readerConfig)
	if err != nil {
		return nil, err
	}
	readerConfig.Subjects = map[string]string{"rac-alert-standing": subjects["rac-alert-standing"]}
	discoveryAuth, err := NewStandingReader(readerConfig)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/internal/standing", transport.Handler(standingdb.New(db), auth))
	if documentsEnabled == "true" {
		documentConfig := readerConfig
		documentConfig.Audience = "rac-documents"
		documentConfig.Subjects = map[string]string{"rac-match-standing": subjects["rac-match-standing"], "rac-chat-standing": subjects["rac-chat-standing"]}
		documentAuth, err := NewDocumentsReader(documentConfig)
		if err != nil {
			return nil, err
		}
		mux.Handle("/internal/documents", documentstransport.Handler(documentsdb.New(db), documentAuth))
	}

	mux.Handle("/internal/standing/replay", transport.ReplayHandler(standingdb.New(db), replayAuth))
	mux.Handle("/internal/standing/replay/events", transport.ReplayPageHandler(standingdb.New(db), replayAuth))
	mux.Handle("/internal/standing/replay/accounts", transport.DiscoveryHandler(standingdb.New(db), discoveryAuth))
	return &http.Server{Addr: ":8082", Handler: mux, ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 32768}, nil
}
