package httpapi

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"strings"
)

type registryReference struct {
	Locale        string `json:"locale"`
	Version       uint64 `json:"version"`
	PolicyVersion string `json:"policy_version"`
}
type registryView struct {
	registryReference
	Summary []string `json:"summary"`
}

// One statement returns metadata and documents from one committed active set.
// Publishing another reviewed document does not silently activate it.
func (s *Server) activeDocuments(c *gin.Context, locale string, subject any) {
	var registry registryView
	registry.Locale = locale
	var itemsJSON, summaryJSON []byte
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT r.version,r.policy_version,to_json(r.summary),
 COALESCE((SELECT json_agg(json_build_object('id',d.id,'kind',d.kind,'version',d.version,
  'locale',d.locale,'sha256',encode(d.content_sha256,'hex'),'material_change',d.material_change,
  'published_at',d.published_at,'accepted_at',a.accepted_at) ORDER BY d.kind)
 FROM documents.requirement req JOIN public.legal_documents d ON d.id=req.document_id
 LEFT JOIN public.usuario u ON u.keycloak_id=$2
 LEFT JOIN public.document_acceptances a ON a.user_id=u.id AND a.document_id=d.id
 WHERE req.locale=r.locale AND req.version=r.version AND d.legal_review='approved'
  AND d.published_at<=statement_timestamp()),'[]'::json)
 FROM documents.head h JOIN documents.registry r ON r.locale=h.locale AND r.version=h.version
 WHERE h.locale=$1`, locale, subject).Scan(&registry.Version, &registry.PolicyVersion, &summaryJSON, &itemsJSON)
	var items []documentView
	if err != nil || json.Unmarshal(summaryJSON, &registry.Summary) != nil || json.Unmarshal(itemsJSON, &items) != nil ||
		registry.Version == 0 || len(registry.Summary) > 3 || len(items) < 4 || len(items) > 5 {
		documentFailure(c)
		return
	}
	for _, summary := range registry.Summary {
		if strings.TrimSpace(summary) == "" || len([]rune(summary)) > 280 {
			documentFailure(c)
			return
		}
	}
	kinds := map[string]bool{}
	for _, item := range items {
		if kinds[item.Kind] {
			documentFailure(c)
			return
		}
		kinds[item.Kind] = true
	}
	for _, kind := range []string{"terms_client", "community_rules", "privacy", "safety_rules"} {
		if !kinds[kind] {
			documentFailure(c)
			return
		}
	}
	c.JSON(200, gin.H{"registry": registry, "items": items})
}
