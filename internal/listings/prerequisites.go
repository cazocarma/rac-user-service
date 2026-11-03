package listings

import (
	"context"
	"database/sql"
	"errors"
)

// ErrPrerequisites means the owner no longer meets a publication requirement.
// Prerequisite checks wrap it; any other error is treated as unavailable.
var ErrPrerequisites = errors.New("listing_owner_prerequisites_required")

// Checked records which owner requirements a check actually evaluated. A
// disabled requirement is stored as false in the decision, never as passed.
type Checked struct {
	Documents bool
	Identity  bool
}

// Prerequisites evaluates documents/identity for the owner with the owner
// service's own credential, inside tx. The approval keeps tx open, with its
// share locks, until it commits, so a registry change cannot slip in between.
type Prerequisites func(ctx context.Context, tx *sql.Tx, ownerSubject string) (Checked, error)
