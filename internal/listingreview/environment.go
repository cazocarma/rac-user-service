package listingreview

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/cazocarma/rac-platform/staff"
	"github.com/cazocarma/rac-user-service/internal/listings"
)

// FromEnvironment serves the three private ingresses on an internal listener
// after an explicit opt-in. Each uses its own provisioned function-only login;
// none is registered on the public customer router.
func FromEnvironment(ownerDB *sql.DB, prerequisites listings.Prerequisites) (*http.Server, error) {
	switch os.Getenv("LISTING_REVIEW_ENABLED") {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, errors.New("invalid listing review activation flag")
	}
	urls := []string{os.Getenv("LISTING_REVIEW_READER_DATABASE_URL"), os.Getenv("LISTING_REVIEW_CORRECTOR_DATABASE_URL"), os.Getenv("LISTING_REVIEW_APPROVER_DATABASE_URL")}
	for i, url := range urls {
		if url == "" || (i > 0 && url == urls[i-1]) || (i == 2 && url == urls[0]) {
			return nil, errors.New("three dedicated listing review databases required")
		}
	}
	access, err := staff.New(os.Getenv("OIDC_ISSUER"), os.Getenv("OIDC_JWKS_URL"), staff.ListingsAudience)
	if err != nil {
		return nil, err
	}
	environment := os.Getenv("RAC_ENV")
	approval := ApprovalPolicy{ListingPolicy: os.Getenv("LISTING_POLICY_VERSION"), AllowProposedActivities: environment == "dev" || environment == "test"}
	policy := os.Getenv("LISTING_REVIEW_POLICY_VERSION")
	var opened []*sql.DB
	fail := func(err error) (*http.Server, error) {
		for _, db := range opened {
			db.Close()
		}
		return nil, err
	}
	for _, url := range urls {
		db, err := sql.Open("postgres", url)
		if err != nil {
			return fail(errors.New("listing review database unavailable"))
		}
		db.SetMaxOpenConns(4)
		db.SetMaxIdleConns(2)
		db.SetConnMaxLifetime(5 * time.Minute)
		opened = append(opened, db)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reader, err := New(ctx, opened[0], access, policy)
	if err != nil {
		return fail(err)
	}
	corrector, err := NewCorrector(ctx, opened[1], access, policy)
	if err != nil {
		return fail(err)
	}
	approver, err := NewApprover(ctx, opened[2], ownerDB, access, policy, approval, prerequisites)
	if err != nil {
		return fail(err)
	}
	return &http.Server{Addr: ":8084", Handler: Combined(reader, corrector, approver), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}, nil
}

// Combined routes each private path to the ingress holding that authority.
// Readiness requires all three; a missing reason catalog leaves it unready.
func Combined(reader *Server, corrector *Corrector, approver *Approver) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		for _, s := range []*Server{reader, corrector.owner, approver.owner} {
			if !s.isReady(r.Context()) {
				problem(w, 503, "listing_review_unavailable")
				return
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte(`{"status":"ready"}`))
	})
	mux.Handle("GET /internal/listings/queue", reader.Handler())
	mux.Handle("GET /internal/listings/revisions/{id}", reader.Handler())
	mux.Handle("GET /internal/listings/revisions/{id}/photo", reader.Handler())
	mux.Handle("POST /internal/listings/revisions/{id}/decisions", corrector.Handler())
	mux.Handle("POST /internal/listings/revisions/{id}/approval", approver.Handler())
	return mux
}
