package identity

import (
	"context"
	"database/sql"
	"errors"
)

// Service records verification state in user's database.
type Service struct {
	db          *sql.DB
	provider    Provider
	fingerprint Fingerprinter
}

func NewService(db *sql.DB, provider Provider, fingerprint Fingerprinter) (*Service, error) {
	if db == nil || provider == nil || !providerPattern.MatchString(provider.Name()) || fingerprint.keyID == "" {
		return nil, errors.New("identity service requires a database, provider and fingerprint key")
	}
	return &Service{db: db, provider: provider, fingerprint: fingerprint}, nil
}

func (s *Service) Provider() Provider { return s.provider }

// Current reports the person's identity state. Any approval is the identity
// result; otherwise the latest attempt is reported. Email state is irrelevant.
func (s *Service) Current(ctx context.Context, subject string) (Status, error) {
	var status sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(
 (SELECT 'approved' FROM identity_verifications v WHERE v.user_id=u.id AND v.status='approved' LIMIT 1),
 (SELECT v.status FROM identity_verifications v WHERE v.user_id=u.id ORDER BY v.created_at DESC, v.id DESC LIMIT 1))
 FROM usuario u WHERE u.keycloak_id=$1`, subject).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return None, ErrNoProfile
	}
	if err != nil {
		return None, ErrUnavailable
	}
	if !status.Valid {
		return None, nil
	}
	return Status(status.String), nil
}

// Start opens a provider session unless the person is already approved. The
// provider is called outside any lock; a session whose row fails to commit is
// unknown to RAC and its webhook is refused.
func (s *Service) Start(ctx context.Context, subject string, purpose Purpose) (Status, Session, error) {
	if !purpose.Valid() {
		return None, Session{}, ErrInvalidResult
	}
	status, err := s.Current(ctx, subject)
	if err != nil {
		return None, Session{}, err
	}
	if status == Approved {
		return Approved, Session{}, nil
	}
	session, err := s.provider.CreateSession(ctx, "", purpose)
	if err != nil || !referencePattern.MatchString(session.ProviderRef) || session.URL == "" {
		return None, Session{}, ErrUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return None, Session{}, ErrUnavailable
	}
	defer tx.Rollback()
	var user string
	// Serializes attempts per person without blocking profile references.
	err = tx.QueryRowContext(ctx, `SELECT id::text FROM usuario WHERE keycloak_id=$1 FOR NO KEY UPDATE`, subject).Scan(&user)
	if errors.Is(err, sql.ErrNoRows) {
		return None, Session{}, ErrNoProfile
	}
	if err != nil {
		return None, Session{}, ErrUnavailable
	}
	var approved bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM identity_verifications WHERE user_id=$1 AND status='approved')`, user).Scan(&approved); err != nil {
		return None, Session{}, ErrUnavailable
	}
	if approved {
		return Approved, Session{}, tx.Commit()
	}
	// A new attempt supersedes an unfinished one for the same purpose.
	if _, err = tx.ExecContext(ctx, `UPDATE identity_verifications SET status='expired',decided_at=statement_timestamp(),updated_at=statement_timestamp()
 WHERE user_id=$1 AND purpose=$2 AND status='pending'`, user, string(purpose)); err != nil {
		return None, Session{}, ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO identity_verifications(user_id,provider,provider_ref,purpose) VALUES($1,$2,$3,$4)`,
		user, s.provider.Name(), session.ProviderRef, string(purpose)); err != nil {
		return None, Session{}, ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return None, Session{}, ErrUnavailable
	}
	return Pending, session, nil
}

// Apply records a verified provider result exactly once. A replayed event id
// is accepted without effect; a different final result for a decided session
// is a conflict. The identity key is used for the fingerprint and discarded.
func (s *Service) Apply(ctx context.Context, result Result) (Status, error) {
	if result.Validate() != nil {
		return None, ErrInvalidResult
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return None, ErrUnavailable
	}
	defer tx.Rollback()
	var id, user string
	var current Status
	err = tx.QueryRowContext(ctx, `SELECT id::text,user_id::text,status FROM identity_verifications
 WHERE provider=$1 AND provider_ref=$2 FOR UPDATE`, s.provider.Name(), result.ProviderRef).Scan(&id, &user, &current)
	if errors.Is(err, sql.ErrNoRows) {
		return None, ErrUnknownSession
	}
	if err != nil {
		return None, ErrUnavailable
	}
	inserted, err := tx.ExecContext(ctx, `INSERT INTO identity_webhook_events(provider,event_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,
		s.provider.Name(), result.EventID)
	if err != nil {
		return None, ErrUnavailable
	}
	if rows, _ := inserted.RowsAffected(); rows == 0 {
		return current, nil
	}
	if current != Pending {
		return current, ErrConflict
	}
	var fingerprint []byte
	var banned, duplicate bool
	if result.Outcome == Approved && result.Adult != nil && *result.Adult {
		fingerprint = s.fingerprint.Fingerprint(result.DocumentCountry, result.IdentityKey)
		// Concurrent approvals of the same identity for two accounts serialize here.
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(encode($1::bytea,'hex'),7))`, fingerprint); err != nil {
			return None, ErrUnavailable
		}
		err = tx.QueryRowContext(ctx, `SELECT
 EXISTS(SELECT FROM banned_identity_fingerprints WHERE key_id=$1 AND fingerprint=$2),
 EXISTS(SELECT FROM identity_verifications WHERE fingerprint_key_id=$1 AND document_fingerprint=$2 AND user_id<>$3 AND status IN ('approved','needs_review'))`,
			s.fingerprint.keyID, fingerprint, user).Scan(&banned, &duplicate)
		if err != nil {
			return None, ErrUnavailable
		}
	}
	status := Decide(result, banned, duplicate)
	// A nil []byte reaches PostgreSQL as an empty bytea, not NULL.
	var stored, keyID any
	if fingerprint != nil {
		stored, keyID = fingerprint, s.fingerprint.keyID
	}
	var country any
	if result.DocumentCountry != "" {
		country = result.DocumentCountry
	}
	if _, err = tx.ExecContext(ctx, `UPDATE identity_verifications SET status=$2,is_adult=$3,document_country=$4,
 document_fingerprint=$5,fingerprint_key_id=$6,decided_at=statement_timestamp(),updated_at=statement_timestamp() WHERE id=$1`,
		id, string(status), result.Adult, country, stored, keyID); err != nil {
		return None, ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return None, ErrUnavailable
	}
	return status, nil
}
