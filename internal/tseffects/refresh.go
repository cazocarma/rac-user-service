package tseffects

import (
	"context"
	"database/sql"
	"time"

	"github.com/lib/pq"
)

// Functions is the exact database authority of the consumer login.
func Functions() []string {
	return []string{"standing.apply_ts_effect(uuid,jsonb,uuid)", "standing.refresh_ts_standing(uuid,uuid,uuid)",
		"standing.ts_expiries_due(integer)"}
}

// Expiries finds accounts whose timed effects ran out and whose stored
// standing no longer matches, and re-derives each one. The database decides
// what is due; refreshing an account that already changed is a no-op.
type Expiries interface {
	Due(ctx context.Context, limit int) ([]string, error)
	Refresh(ctx context.Context, subject string) (bool, error)
}

type PostgresExpiries struct {
	DB     *sql.DB
	Policy string
}

func (p PostgresExpiries) Due(ctx context.Context, limit int) ([]string, error) {
	var subjects []string
	err := p.DB.QueryRowContext(ctx, `SELECT standing.ts_expiries_due($1)`, limit).Scan(pq.Array(&subjects))
	return subjects, err
}

func (p PostgresExpiries) Refresh(ctx context.Context, subject string) (bool, error) {
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var changed sql.NullBool
	// A fresh audit event per refresh; the derivation itself is idempotent.
	if err := tx.QueryRowContext(ctx, `SELECT (standing.refresh_ts_standing(gen_random_uuid(),$1,$2)->>'changed')::boolean`,
		subject, p.Policy).Scan(&changed); err != nil {
		return false, err
	}
	return changed.Bool, tx.Commit()
}

// Batch is the most accounts refreshed per pass.
const Batch = 50

// SweepExpiries refreshes one bounded batch. It returns how many accounts
// changed. A failing account stops the pass; the next pass retries it.
func SweepExpiries(ctx context.Context, store Expiries) (int, error) {
	subjects, err := store.Due(ctx, Batch)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, subject := range subjects {
		if !eventID.MatchString(subject) {
			continue
		}
		did, err := store.Refresh(ctx, subject)
		if err != nil {
			return changed, err
		}
		if did {
			changed++
		}
	}
	return changed, nil
}

// RefreshLoop sweeps every interval until ctx ends. report receives the
// number of accounts changed and whether the pass failed; it never sees
// subjects.
func RefreshLoop(ctx context.Context, store Expiries, interval time.Duration, report func(changed int, err error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		pass, cancel := context.WithTimeout(ctx, interval)
		changed, err := SweepExpiries(pass, store)
		cancel()
		if ctx.Err() != nil {
			return
		}
		report(changed, err)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
