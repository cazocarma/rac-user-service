// Package postgres reads document prerequisites with the user owner's scoped
// database identity. Other services must use authenticated internal transport.
package postgres

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/cazocarma/rac-platform/documents"
	"github.com/cazocarma/rac-platform/policy"
)

type Queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type Source struct{ db Queryer }

func New(db Queryer) *Source { return &Source{db: db} }

// One statement binds registry, immutable lineage and the subject's acceptances
// to one committed PostgreSQL snapshot. No latest-publication fallback: only an
// explicitly activated registry supplies requirements. The verified OIDC subject
// is resolved through usuario; public request IDs never choose a local account.
const snapshotSQL = `SELECT r.version,r.policy_version,r.approved_by,r.effective_at,statement_timestamp(),
 COALESCE((SELECT jsonb_agg(jsonb_build_object('id',d.id,'kind',d.kind,
  'material',l.material_version,'hash',encode(d.content_sha256,'hex'),
  'published',d.published_at,'approved',d.legal_review='approved') ORDER BY d.kind)
  FROM documents.requirement req JOIN public.legal_documents d ON d.id=req.document_id
  JOIN documents.lineage l ON l.document_id=d.id
  WHERE req.locale=r.locale AND req.version=r.version),'[]'::jsonb),
 COALESCE((SELECT jsonb_agg(jsonb_build_object('id',a.id,'kind',a.kind,
  'material',a.material_version,'hash',encode(a.content_sha256,'hex'),
  'accepted',a.accepted_at) ORDER BY a.kind)
  FROM (SELECT DISTINCT ON(d.kind) d.id,d.kind,d.content_sha256,l.material_version,consent.accepted_at
   FROM public.document_acceptances consent JOIN public.legal_documents d ON d.id=consent.document_id
   JOIN documents.lineage l ON l.document_id=d.id
   JOIN documents.requirement req ON req.locale=r.locale AND req.version=r.version AND req.kind=d.kind
   JOIN documents.lineage active ON active.document_id=req.document_id AND active.material_version=l.material_version
   WHERE consent.user_id=u.id AND d.locale=r.locale
   ORDER BY d.kind,consent.accepted_at,d.id) a),'[]'::jsonb)
 FROM documents.head h JOIN documents.registry r ON r.locale=h.locale AND r.version=h.version
 JOIN public.usuario u ON u.keycloak_id=$1 WHERE h.locale=$2`

type record struct {
	ID        string         `json:"id"`
	Kind      documents.Kind `json:"kind"`
	Material  string         `json:"material"`
	Hash      string         `json:"hash"`
	Published time.Time      `json:"published"`
	Approved  bool           `json:"approved"`
	Accepted  time.Time      `json:"accepted"`
}

func digest(value string) ([32]byte, error) {
	var result [32]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != len(result) {
		return result, documents.ErrUnavailable
	}
	copy(result[:], raw)
	return result, nil
}
func (s *Source) ReadDocuments(ctx context.Context, q documents.Query) (documents.Observation, error) {
	fail := func() (documents.Observation, error) { return documents.Observation{}, documents.ErrUnavailable }
	if s == nil || s.db == nil || ctx == nil || ctx.Err() != nil || !q.Valid() {
		return fail()
	}
	o := documents.Observation{Query: q}
	var current, accepted []byte
	err := s.db.QueryRowContext(ctx, snapshotSQL, q.AccountID, q.Locale).Scan(&o.Revision,
		&o.Snapshot.Policy.ID, &o.Snapshot.Policy.ApprovedBy, &o.Snapshot.Policy.EffectiveAt,
		&o.Snapshot.ObservedAt, &current, &accepted)
	if err != nil || o.Revision == 0 {
		return fail()
	}
	o.Snapshot.Policy.State = policy.Approved
	var docs, consents []record
	if json.Unmarshal(current, &docs) != nil || json.Unmarshal(accepted, &consents) != nil {
		return fail()
	}
	for _, d := range docs {
		hash, err := digest(d.Hash)
		if err != nil {
			return fail()
		}
		o.Snapshot.Documents = append(o.Snapshot.Documents, documents.Document{ID: d.ID, Kind: d.Kind,
			MaterialVersion: d.Material, SHA256: hash, PublishedAt: d.Published, Approved: d.Approved})
	}
	for _, a := range consents {
		hash, err := digest(a.Hash)
		if err != nil {
			return fail()
		}
		o.Snapshot.Acceptances = append(o.Snapshot.Acceptances, documents.Acceptance{DocumentID: a.ID, Kind: a.Kind,
			MaterialVersion: a.Material, SHA256: hash, AcceptedAt: a.Accepted})
	}
	if err := documents.RequireAcceptedDocuments(o.Snapshot, q.Role, q.Capability); err != nil && !errors.Is(err, documents.ErrRequired) {
		return fail()
	}
	return o, nil
}

var _ documents.Source = (*Source)(nil)
