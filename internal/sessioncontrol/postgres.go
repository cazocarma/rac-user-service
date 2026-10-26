package sessioncontrol

import (
	"context"
	"database/sql"
	"encoding/json"
)

type Postgres struct{ DB *sql.DB }

func (p *Postgres) Claim(ctx context.Context) (*Work, error) {
	w := &Work{}
	var raw []byte
	err := p.DB.QueryRowContext(ctx, `SELECT event_id,subject_id,version,keycloak_subject,sessions,next_index,claim_token FROM standing.claim_session_effect()`).
		Scan(&w.Event, &w.Subject, &w.Version, &w.KeycloakSubject, &raw, &w.Next, &w.Claim)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	if raw != nil && (decode(raw, &w.Sessions) != nil || w.Sessions == nil || !validRefs(w.Sessions)) {
		return nil, ErrUnavailable
	}
	return w, nil
}

func acknowledged(row *sql.Row) error {
	var applied bool
	if row.Scan(&applied) != nil {
		return ErrUnavailable
	}
	if !applied {
		return ErrClaimLost
	}
	return nil
}

func (p *Postgres) Capture(ctx context.Context, w *Work, refs []Ref) error {
	if refs == nil || !validRefs(refs) {
		return ErrUnavailable
	}
	raw, err := json.Marshal(refs)
	if err != nil {
		return ErrUnavailable
	}
	return acknowledged(p.DB.QueryRowContext(ctx, `SELECT standing.capture_sessions($1,$2,$3::jsonb)`, w.Event, w.Claim, string(raw)))
}

func (p *Postgres) Advance(ctx context.Context, w *Work, next int) error {
	return acknowledged(p.DB.QueryRowContext(ctx, `SELECT standing.advance_sessions($1,$2,$3)`, w.Event, w.Claim, next))
}

func (p *Postgres) Retry(ctx context.Context, w *Work) error {
	return acknowledged(p.DB.QueryRowContext(ctx, `SELECT standing.retry_sessions($1,$2)`, w.Event, w.Claim))
}

func (p *Postgres) Stats(ctx context.Context) (Stats, error) {
	var s Stats
	if p.DB.QueryRowContext(ctx, `SELECT pending,oldest_seconds FROM standing.session_effect_stats()`).Scan(&s.Pending, &s.OldestSeconds) != nil || s.Pending < 0 || s.OldestSeconds < 0 {
		return Stats{}, ErrUnavailable
	}
	return s, nil
}

var _ Store = (*Postgres)(nil)
