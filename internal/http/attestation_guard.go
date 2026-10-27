package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/cazocarma/rac-user-service/internal/attestations"
)

var errAssessmentRequired = errors.New("compa assessment required")
var errAssessmentUnavailable = errors.New("compa assessment unavailable")

// Called only after the document check, inside the writer's own transaction.
// The shared head lease stays held through external role provisioning and commit.
func checkAssessment(ctx context.Context, tx *sql.Tx, subject string) error {
	definition, err := readAssessment(ctx, tx, "es")
	if err != nil {
		return errAssessmentUnavailable
	}
	var declarations, answers []byte
	var passedAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT a.statements,a.answers,a.quiz_passed_at
 FROM usuario u JOIN compa_attestations a ON a.user_id=u.id
 WHERE u.keycloak_id=$1 AND a.definition_id=$2`, subject, definition.ID).Scan(&declarations, &answers, &passedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return errAssessmentRequired
	}
	if err != nil || passedAt.Before(definition.PublishedAt) || passedAt.After(time.Now()) {
		return errAssessmentUnavailable
	}
	input := attestations.Submission{Version: definition.Version, SHA256: definition.SHA256}
	if json.Unmarshal(declarations, &input.Statements) != nil || json.Unmarshal(answers, &input.Answers) != nil {
		return errAssessmentUnavailable
	}
	if _, err = attestations.Evaluate(definition.Definition, input, time.Now()); err != nil {
		return errAssessmentUnavailable
	}
	return nil
}
