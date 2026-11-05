// Package listingreview is the private, authenticated staff ingress owned by
// user-service. It is never registered on the public customer router.
package listingreview

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cazocarma/rac-platform/audit"
	"github.com/cazocarma/rac-platform/staff"
	staffdb "github.com/cazocarma/rac-platform/staff/postgres"
	"github.com/cazocarma/rac-user-service/internal/strictjson"
)

const readySignature = "listing_review.ready()"
const queueSignature = "listing_review.queue(audit.reference,audit.reference,audit.reference,integer,integer,timestamp with time zone,uuid)"
const revisionSignature = "listing_review.revision(audit.reference,audit.reference,audit.reference,audit.reference)"

var signatures = []string{readySignature, queueSignature, revisionSignature}

func rolePolicy() staffdb.RolePolicy {
	return functionPolicy(signatures)
}

func functionPolicy(functions []string) staffdb.RolePolicy {
	return staffdb.RolePolicy{Functions: append([]string(nil), functions...), ForbiddenRoles: []string{"postgres", "rac_user", "rac_match", "rac_chat", "rac_admin", "rac_alert", "rac_migrator", "rac_backup", "rac_seed", "rac_documents_editorial"}}
}

type Server struct {
	db        *sql.DB
	access    *staff.Access
	policy    string
	now       func() time.Time
	authority staffdb.RolePolicy
	readiness string
}

func New(ctx context.Context, db *sql.DB, access *staff.Access, policy string) (*Server, error) {
	return newServer(ctx, db, access, policy, rolePolicy())
}

func newServer(ctx context.Context, db *sql.DB, access *staff.Access, policy string, authority staffdb.RolePolicy) (*Server, error) {
	if db == nil || access == nil || !audit.ValidID(policy) {
		return nil, errors.New("invalid listing review configuration")
	}
	if err := staffdb.CheckRole(ctx, db, authority); err != nil {
		return nil, errors.New("listing review database privileges not isolated")
	}
	var ready bool
	if err := db.QueryRowContext(ctx, `SELECT listing_review.ready()`).Scan(&ready); err != nil || !ready {
		return nil, errors.New("listing review database not ready")
	}
	return &Server{db: db, access: access, policy: policy, now: time.Now, authority: authority, readiness: `SELECT listing_review.ready()`}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", s.ready)
	mux.Handle("GET /internal/listings/queue", s.access.Require(staff.ListingsRead, http.HandlerFunc(s.queue)))
	mux.Handle("GET /internal/listings/revisions/{id}", s.access.Require(staff.ListingsRead, http.HandlerFunc(s.revision)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func (s *Server) isReady(parent context.Context) bool {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	var ready bool
	return s.db != nil && staffdb.CheckRole(ctx, s.db, s.authority) == nil && s.db.QueryRowContext(ctx, s.readiness).Scan(&ready) == nil && ready
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if !s.isReady(r.Context()) {
		problem(w, 503, "listing_review_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write([]byte(`{"status":"ready"}`))
}

type cursor struct {
	Risk int    `json:"risk"`
	At   string `json:"at"`
	ID   string `json:"id"`
}
type queueItem struct {
	ID             string `json:"id"`
	ListingID      string `json:"listing_id"`
	ListingVersion string `json:"listing_version"`
	RevisionNo     string `json:"revision_no"`
	Risk           int    `json:"risk_score"`
	SubmittedAt    string `json:"submitted_at"`
	SHA256         string `json:"sha256"`
	PolicyVersion  string `json:"policy_version"`
}

func decodeCursor(encoded string) (cursor, time.Time, error) {
	var value cursor
	var input struct {
		Risk *int   `json:"risk"`
		At   string `json:"at"`
		ID   string `json:"id"`
	}
	if len(encoded) > 512 {
		return value, time.Time{}, errors.New("invalid cursor")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || strictjson.Decode(strings.NewReader(string(raw)), &input) != nil || input.Risk == nil {
		return value, time.Time{}, errors.New("invalid cursor")
	}
	value = cursor{Risk: *input.Risk, At: input.At, ID: input.ID}
	if !audit.ValidID(value.ID) || value.Risk < 0 || value.Risk > 100 {
		return value, time.Time{}, errors.New("invalid cursor")
	}
	at, err := time.Parse(time.RFC3339Nano, value.At)
	if err != nil || at.IsZero() || at.Location() != time.UTC {
		return value, time.Time{}, errors.New("invalid cursor")
	}
	return value, at, nil
}

func eventID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:]), nil
}

// The caller receives buffered content only AFTER its audit transaction commits
// and the verified session passes its final MFA check. No callback writes HTTP
// bytes or leaks a DB diagnostic before that boundary.
func (s *Server) read(w http.ResponseWriter, r *http.Request, query string, args ...any) ([]byte, bool) {
	session, ok := staff.Principal(r.Context())
	if !ok {
		problem(w, 401, "staff_authentication_required")
		return nil, false
	}
	id, err := eventID()
	if err != nil {
		problem(w, 503, "listing_review_unavailable")
		return nil, false
	}
	parameters := append([]any{id, session.Subject, s.policy}, args...)
	raw, err := s.transaction(r.Context(), session, staff.ListingsRead, query, parameters...)
	if err != nil {
		reviewFailure(w, err)
		return nil, false
	}
	return raw, true
}

// Both private ingresses share the same role/session/commit boundary. The
// correction credential has no queue/detail authority and vice versa.
func (s *Server) transaction(parent context.Context, session staff.Session, permission staff.Permission, query string, parameters ...any) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	if staffdb.CheckRole(ctx, s.db, s.authority) != nil {
		return nil, errUnavailable
	}
	if err := session.Check(permission, s.now()); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, errUnavailable
	}
	defer tx.Rollback()
	var raw []byte
	if err = tx.QueryRowContext(ctx, query, parameters...).Scan(&raw); err != nil {
		return nil, err
	}
	if len(raw) > 128*1024 || (len(raw) > 0 && !json.Valid(raw)) {
		return nil, errUnavailable
	}
	if err = session.Check(permission, s.now()); err != nil {
		return nil, err
	}
	if tx.Commit() != nil {
		return nil, errUnavailable
	}
	return raw, nil
}

func noBody(r *http.Request) bool { return r.ContentLength == 0 && len(r.TransferEncoding) == 0 }

func (s *Server) queue(w http.ResponseWriter, r *http.Request) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !noBody(r) || len(r.URL.RawQuery) > 1024 || (r.URL.ForceQuery && r.URL.RawQuery == "") {
		problem(w, 400, "invalid_listing_review_query")
		return
	}
	for key, items := range values {
		if (key != "limit" && key != "cursor") || len(items) != 1 || items[0] == "" {
			problem(w, 400, "invalid_listing_review_query")
			return
		}
	}
	limit := 20
	if value := values.Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
	}
	if err != nil || limit < 1 || limit > 50 {
		problem(w, 400, "invalid_listing_review_query")
		return
	}
	var score, at, id any
	if value := values.Get("cursor"); value != "" {
		decoded, stamp, err := decodeCursor(value)
		if err != nil {
			problem(w, 400, "invalid_listing_review_query")
			return
		}
		score, at, id = decoded.Risk, stamp, decoded.ID
	}
	raw, ok := s.read(w, r, `SELECT listing_review.queue($1,$2,$3,$4,$5,$6,$7)`, limit, score, at, id)
	if !ok {
		return
	}
	var items []queueItem
	if json.Unmarshal(raw, &items) != nil || len(items) > limit+1 {
		problem(w, 503, "listing_review_unavailable")
		return
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		encoded, _ := json.Marshal(cursor{Risk: last.Risk, At: last.SubmittedAt, ID: last.ID})
		next = base64.RawURLEncoding.EncodeToString(encoded)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]any{"items": items, "next_cursor": next})
}

func (s *Server) revision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !noBody(r) || r.URL.RawQuery != "" || r.URL.ForceQuery || !audit.ValidID(id) {
		problem(w, 400, "invalid_listing_review_query")
		return
	}
	raw, ok := s.read(w, r, `SELECT listing_review.revision($1,$2,$3,$4)`, id)
	if !ok {
		return
	}
	if len(raw) == 0 || string(raw) == "null" {
		problem(w, 404, "listing_revision_not_found")
		return
	}
	if !json.Valid(raw) {
		problem(w, 503, "listing_review_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(raw)
}
