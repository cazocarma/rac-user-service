package listingreview

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/cazocarma/rac-user-service/internal/listings"
)

// The returned owner transaction holds requirement/registry locks until the
// writer commits. No storage I/O belongs inside either transaction.
func checkedApprovalRequirements(ctx context.Context, ownerDB *sql.DB, check listings.Prerequisites, allowProposed bool, raw []byte) ([]byte, *sql.Tx, error) {
	var state struct {
		Replay       *bool           `json:"replay"`
		Owner        string          `json:"owner_subject"`
		Requirements json.RawMessage `json:"requirements"`
	}
	if json.Unmarshal(raw, &state) != nil || state.Replay == nil || (!*state.Replay && state.Owner == "") || (*state.Replay && len(state.Requirements) == 0) {
		return nil, nil, errUnavailable
	}
	if *state.Replay {
		return state.Requirements, nil, nil
	}
	tx, err := ownerDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, errUnavailable
	}
	checked, err := check(ctx, tx, state.Owner)
	if err != nil {
		tx.Rollback()
		if errors.Is(err, listings.ErrPrerequisites) {
			return nil, nil, listings.ErrPrerequisites
		}
		return nil, nil, errUnavailable
	}
	requirements, _ := json.Marshal(map[string]bool{"documents": checked.Documents, "identity": checked.Identity, "allow_proposed_activities": allowProposed})
	return requirements, tx, nil
}
