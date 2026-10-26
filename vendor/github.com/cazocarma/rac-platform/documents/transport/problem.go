package transport

import (
	"encoding/hex"
	"errors"

	"github.com/cazocarma/rac-platform/documents"
)

type PendingDocument struct {
	ID              string         `json:"id"`
	Kind            documents.Kind `json:"kind"`
	SHA256          string         `json:"sha256"`
	MaterialVersion string         `json:"material_version"`
}
type Problem struct {
	Error     string            `json:"error"`
	Documents []PendingDocument `json:"documents,omitempty"`
}

// Failure provides the same public precondition response to all writers. It
// never includes acceptance history, legal text or internal driver diagnostics.
func Failure(err error) (int, Problem) {
	var required *documents.RequiredError
	if errors.As(err, &required) && len(required.Documents) > 0 && len(required.Documents) <= 5 {
		result := Problem{Error: "DOCUMENT_ACCEPTANCE_REQUIRED"}
		for _, d := range required.Documents {
			result.Documents = append(result.Documents, PendingDocument{ID: d.ID, Kind: d.Kind, SHA256: hex.EncodeToString(d.SHA256[:]), MaterialVersion: d.MaterialVersion})
		}
		return 428, result
	}
	return 503, Problem{Error: "documents_unavailable"}
}
