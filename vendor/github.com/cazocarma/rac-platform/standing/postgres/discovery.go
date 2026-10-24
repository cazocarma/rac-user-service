package postgres

import (
	"context"
	"github.com/cazocarma/rac-platform/standing"
)

func (s *Source) Discover(ctx context.Context, after string) (standing.DiscoveryPage, error) {
	p := standing.DiscoveryPage{After: after, Accounts: make([]standing.ChangedAccount, 0)}
	if s.db == nil || (after != "" && !standing.ValidAccountID(after)) {
		return p, standing.ErrUnavailable
	}
	var cursor any
	if after != "" {
		cursor = after
	}
	rows, err := s.db.QueryContext(ctx, `SELECT subject_id::text,version FROM standing.account
 WHERE version>1 AND ($1::uuid IS NULL OR subject_id>$1::uuid)
 ORDER BY subject_id LIMIT 101`, cursor)
	if err != nil {
		return p, standing.ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var account standing.ChangedAccount
		if err = rows.Scan(&account.Subject, &account.Version); err != nil {
			return p, standing.ErrUnavailable
		}
		p.Accounts = append(p.Accounts, account)
	}
	if rows.Err() != nil {
		return p, standing.ErrUnavailable
	}
	p.HasMore = len(p.Accounts) > 100
	if p.HasMore {
		p.Accounts = p.Accounts[:100]
	}
	if len(p.Accounts) > 0 {
		p.Next = p.Accounts[len(p.Accounts)-1].Subject
	}
	if !p.Valid() {
		return standing.DiscoveryPage{}, standing.ErrUnavailable
	}
	return p, nil
}
