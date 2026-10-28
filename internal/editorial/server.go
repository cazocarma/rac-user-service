// Package editorial owns the private staff ingress for document commands.
// It is never registered on the consumer API router.
package editorial

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cazocarma/rac-platform/audit"
	"github.com/cazocarma/rac-platform/staff"
	"github.com/cazocarma/rac-user-service/internal/strictjson"
	"github.com/lib/pq"
)

var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

const draftSignature = "documents.draft_document(audit.reference,audit.reference,audit.reference,audit.reference,text,text,text,text,boolean,audit.digest)"
const reviewSignature = "documents.review_document(audit.reference,audit.reference,audit.reference,audit.reference,audit.digest,text)"
const publishSignature = "documents.publish_document(audit.reference,audit.reference,audit.reference,audit.reference,audit.digest)"
const readSignature = "documents.read_editorial_document(uuid)"
const readySignature = "documents.editorial_ready()"
const registryReadSignature = "documents.read_editorial_registry(text)"

var requiredSignatures = []string{draftSignature, reviewSignature, publishSignature, readSignature, readySignature,
	assessmentDraftSignature, assessmentReviewSignature, assessmentPublishSignature, assessmentReadSignature, bundleSignature, registryReadSignature}

type Server struct {
	db     *sql.DB
	access *staff.Access
	policy string
	now    func() time.Time
}

// A dedicated login may execute only the reviewed ingress functions. Sharing
// rac_user, an owner/superuser, DML rights or raw activation is rejected.
func New(ctx context.Context, db *sql.DB, access *staff.Access, policy string) (*Server, error) {
	if db == nil || access == nil || !audit.ValidID(policy) {
		return nil, errors.New("invalid editorial configuration")
	}
	var allowed bool
	err := db.QueryRowContext(ctx, `SELECT current_user=session_user AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
 AND NOT EXISTS(SELECT FROM pg_auth_members m WHERE m.member=r.oid)
 AND session_user NOT IN('rac_user','rac_match','rac_chat','rac_alert','rac_backup','rac_seed','rac_migrator')
 AND NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN('public','audit','documents','standing') AND c.relkind IN('r','p','v','m','f') AND NOT EXISTS(SELECT FROM pg_depend d WHERE d.classid='pg_class'::regclass AND d.objid=c.oid AND d.deptype='e') AND has_table_privilege(session_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
 AND NOT EXISTS(SELECT FROM unnest($1::text[]) signature WHERE NOT has_function_privilege(session_user,signature,'EXECUTE')) AND documents.editorial_ready()
 AND NOT has_function_privilege(session_user,'documents.activate(uuid,bigint,text,uuid[],uuid,uuid,text[])','EXECUTE')
 AND NOT has_function_privilege(session_user,'documents.editorial_record(uuid,uuid,uuid,uuid,text,jsonb)','EXECUTE')
 AND NOT has_function_privilege(session_user,'audit.append(uuid,text,uuid,text,uuid,uuid)','EXECUTE')
 FROM pg_roles r WHERE r.rolname=session_user`, pq.Array(requiredSignatures)).Scan(&allowed)
	if err != nil || !allowed {
		return nil, errors.New("editorial database privileges not isolated")
	}
	return &Server{db: db, access: access, policy: policy, now: time.Now}, nil
}
func FromEnvironment() (*http.Server, error) {
	switch os.Getenv("DOCUMENT_EDITORIAL_ENABLED") {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, errors.New("invalid editorial activation flag")
	}
	if os.Getenv("DOCUMENT_EDITORIAL_DATABASE_URL") == "" {
		return nil, errors.New("dedicated editorial database required")
	}
	access, err := staff.New(os.Getenv("OIDC_ISSUER"), os.Getenv("OIDC_JWKS_URL"), staff.DocumentsAudience)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("postgres", os.Getenv("DOCUMENT_EDITORIAL_DATABASE_URL"))
	if err != nil {
		return nil, errors.New("editorial database unavailable")
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	owner, err := New(ctx, db, access, os.Getenv("DOCUMENT_EDITORIAL_POLICY_VERSION"))
	if err != nil {
		db.Close()
		return nil, err
	}
	return &http.Server{Addr: ":8083", Handler: owner.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}, nil
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", s.ready)
	mux.Handle("POST /internal/documents/drafts", s.access.Require(staff.DocumentsDraft, http.HandlerFunc(s.draft)))
	mux.Handle("POST /internal/documents/reviews", s.access.Require(staff.DocumentsApprove, http.HandlerFunc(s.review)))
	mux.Handle("POST /internal/documents/publications", s.access.Require(staff.DocumentsPublish, http.HandlerFunc(s.publish)))
	mux.Handle("GET /internal/documents/{id}", s.access.Require(staff.DocumentsRead, http.HandlerFunc(s.read)))
	mux.Handle("GET /internal/documents/registry/{locale}", s.access.Require(staff.DocumentsRead, http.HandlerFunc(s.readRegistry)))
	mux.Handle("POST /internal/assessments/drafts", s.access.Require(staff.DocumentsDraft, http.HandlerFunc(s.draftAssessment)))
	mux.Handle("POST /internal/assessments/reviews", s.access.Require(staff.DocumentsApprove, http.HandlerFunc(s.reviewAssessment)))
	mux.Handle("POST /internal/assessments/publications", s.access.Require(staff.DocumentsPublish, http.HandlerFunc(s.publishAssessment)))
	mux.Handle("GET /internal/assessments/{id}", s.access.Require(staff.DocumentsRead, http.HandlerFunc(s.readAssessment)))
	mux.Handle("POST /internal/documents/activations", s.access.Require(staff.DocumentsActivate, http.HandlerFunc(s.activateBundle)))

	return mux
}

type command struct {
	EventID    string `json:"event_id"`
	DocumentID string `json:"document_id"`
	SHA256     string `json:"sha256"`
}
type draftRequest struct {
	command
	Kind           string `json:"kind"`
	Version        string `json:"version"`
	Locale         string `json:"locale"`
	Content        string `json:"content"`
	MaterialChange *bool  `json:"material_change"`
}
type reviewRequest struct {
	command
	Decision string `json:"decision"`
}

func valid(c command) bool {
	return audit.ValidID(c.EventID) && audit.ValidID(c.DocumentID) && digestPattern.MatchString(c.SHA256)
}
func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		problem(w, 400, "invalid_editorial_command")
		return false
	}
	if strictjson.Decode(http.MaxBytesReader(w, r.Body, 1048576), target) != nil {
		problem(w, 400, "invalid_editorial_command")
		return false
	}
	return true
}
func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
func fail(w http.ResponseWriter, err error) {
	if errors.Is(err, staff.ErrStepUp) || errors.Is(err, staff.ErrForbidden) {
		status, code := staff.Failure(err)
		problem(w, status, code)
		return
	}
	var pg *pq.Error
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505", "40001":
			problem(w, 409, "editorial_revision_conflict")
			return
		case "22023", "23514":
			problem(w, 400, "invalid_editorial_command")
			return
		case "42501":
			if pg.Message == "editorial_self_review" {
				problem(w, 403, "editorial_self_review")
				return
			}
		}
	}
	problem(w, 503, "editorial_unavailable")
}
func (s *Server) execute(w http.ResponseWriter, r *http.Request, permission staff.Permission, statement string, args ...any) {
	s.transact(w, r, permission, func(ctx context.Context, tx *sql.Tx, actor, policy string) (any, error) {
		args = append(args, actor, policy)
		var id string
		err := tx.QueryRowContext(ctx, statement, args...).Scan(&id)
		return map[string]string{"document_id": id}, err
	})
}
func (s *Server) transact(w http.ResponseWriter, r *http.Request, permission staff.Permission, operation func(context.Context, *sql.Tx, string, string) (any, error)) {

	session, ok := staff.Principal(r.Context())
	if !ok {
		problem(w, 401, "invalid_staff_token")
		return
	}
	if err := session.Check(permission, s.now()); err != nil {
		fail(w, err)
		return
	}
	deadline := s.now().Add(5 * time.Second)
	if session.ExpiresAt.Before(deadline) {
		deadline = session.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		fail(w, err)
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='2000ms'"); err != nil {
		fail(w, err)
		return
	}
	// Actor and policy originate only at this verified boundary.
	result, err := operation(ctx, tx, session.Subject, s.policy)
	if err != nil {
		if freshness := session.Check(permission, s.now()); freshness != nil {
			fail(w, freshness)
		} else {
			fail(w, err)
		}
		return
	}

	if err = session.Check(permission, s.now()); err != nil {
		fail(w, err)
		return
	}
	if err = tx.Commit(); err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
func (s *Server) draft(w http.ResponseWriter, r *http.Request) {
	var body draftRequest
	if !decode(w, r, &body) {
		return
	}
	kinds := map[string]bool{"terms_client": true, "terms_compa": true, "community_rules": true, "privacy": true, "safety_rules": true}
	hash := sha256.Sum256([]byte(body.Content))
	if !valid(body.command) || !kinds[body.Kind] || !versionPattern.MatchString(body.Version) || (body.Locale != "es" && body.Locale != "en") || body.MaterialChange == nil || !utf8.ValidString(body.Content) || strings.ContainsRune(body.Content, 0) || len(body.Content) > 131072 || strings.TrimSpace(body.Content) == "" || hex.EncodeToString(hash[:]) != body.SHA256 {
		problem(w, 400, "invalid_editorial_command")
		return
	}
	s.execute(w, r, staff.DocumentsDraft, `SELECT documents.draft_document($1::audit.reference,$2::audit.reference,$9::audit.reference,$10::audit.reference,$3,$4,$5,$6,$7,$8::audit.digest)`, body.EventID, body.DocumentID, body.Kind, body.Version, body.Locale, body.Content, *body.MaterialChange, body.SHA256)
}
func (s *Server) review(w http.ResponseWriter, r *http.Request) {
	var body reviewRequest
	if !decode(w, r, &body) {
		return
	}
	if !valid(body.command) || (body.Decision != "approved" && body.Decision != "rejected") {
		problem(w, 400, "invalid_editorial_command")
		return
	}
	s.execute(w, r, staff.DocumentsApprove, `SELECT documents.review_document($1::audit.reference,$2::audit.reference,$5::audit.reference,$6::audit.reference,$3::audit.digest,$4)`, body.EventID, body.DocumentID, body.SHA256, body.Decision)
}
func (s *Server) publish(w http.ResponseWriter, r *http.Request) {
	var body command
	if !decode(w, r, &body) {
		return
	}
	if !valid(body) {
		problem(w, 400, "invalid_editorial_command")
		return
	}
	s.execute(w, r, staff.DocumentsPublish, `SELECT documents.publish_document($1::audit.reference,$2::audit.reference,$4::audit.reference,$5::audit.reference,$3::audit.digest)`, body.EventID, body.DocumentID, body.SHA256)
}
func (s *Server) read(w http.ResponseWriter, r *http.Request) {
	s.readResource(w, r, "SELECT documents.read_editorial_document($1)")
}
func (s *Server) readRegistry(w http.ResponseWriter, r *http.Request) {
	locale := r.PathValue("locale")
	if (locale != "es" && locale != "en") || r.URL.RawQuery != "" || r.URL.ForceQuery {
		problem(w, 400, "invalid_editorial_command")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var version int64
	if err := s.db.QueryRowContext(ctx, "SELECT documents.read_editorial_registry($1)", locale).Scan(&version); err != nil || version < 0 {
		problem(w, 503, "editorial_unavailable")
		return
	}
	session, _ := staff.Principal(r.Context())
	if err := session.Check(staff.DocumentsRead, s.now()); err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int64{"registry_version": version})
}
func (s *Server) readResource(w http.ResponseWriter, r *http.Request, query string) {
	if !audit.ValidID(r.PathValue("id")) {
		problem(w, 404, "editorial_document_not_found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var raw []byte
	if err := s.db.QueryRowContext(ctx, query, r.PathValue("id")).Scan(&raw); err != nil {
		fail(w, err)
		return
	}
	if len(raw) == 0 {
		problem(w, 404, "editorial_document_not_found")
		return
	}
	session, _ := staff.Principal(r.Context())
	if err := session.Check(staff.DocumentsRead, s.now()); err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	var ready bool
	if err := s.db.QueryRowContext(ctx, "SELECT documents.editorial_ready()").Scan(&ready); err != nil || !ready {
		problem(w, 503, "editorial_unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
