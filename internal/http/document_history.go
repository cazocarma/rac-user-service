package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cazocarma/rac-platform/standing"
	"github.com/cazocarma/rac-user-service/internal/platform"
	"github.com/gin-gonic/gin"
)

type historyCursor struct {
	Version int       `json:"v"`
	At      time.Time `json:"at"`
	ID      string    `json:"id"`
}
type historyItem struct {
	documentView
	Context string `json:"context"`
}

func historyQuery(query url.Values) (int, *historyCursor, bool) {
	limit := 20
	if values, exists := query["limit"]; exists {
		if len(values) != 1 {
			return 0, nil, false
		}
		var err error
		limit, err = strconv.Atoi(values[0])
		if err != nil || limit < 1 || limit > 50 {
			return 0, nil, false
		}
	}
	values, exists := query["cursor"]
	if !exists {
		return limit, nil, true
	}
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 512 {
		return 0, nil, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(values[0])
	if err != nil {
		return 0, nil, false
	}
	var cursor historyCursor
	if decodeUniqueJSON(bytes.NewReader(raw), &cursor) != nil || cursor.Version != 1 || cursor.At.IsZero() ||
		cursor.At.Year() < 1 || cursor.At.Year() > 9999 || !standing.ValidAccountID(cursor.ID) {
		return 0, nil, false
	}
	cursor.ID = strings.ToLower(cursor.ID)
	return limit, &cursor, true
}

// History is an own-account protective read. A registry change, missing current
// definition, or standing sanction never creates a document prerequisite here.
func (s *Server) documentHistory(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	limit, cursor, ok := historyQuery(c.Request.URL.Query())
	if !ok {
		c.JSON(400, gin.H{"error": "invalid_history_page"})
		return
	}
	var at any
	var id any
	if cursor != nil {
		at = cursor.At
		id = cursor.ID
	}
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT d.id,d.kind,d.version,d.locale,encode(d.content_sha256,'hex'),d.material_change,d.published_at,a.accepted_at,a.context
 FROM usuario u JOIN document_acceptances a ON a.user_id=u.id JOIN legal_documents d ON d.id=a.document_id
 WHERE u.keycloak_id=$1 AND d.legal_review='approved' AND d.published_at<=statement_timestamp()
 AND ($2::timestamptz IS NULL OR (a.accepted_at,a.document_id)<($2::timestamptz,$3::uuid))
 ORDER BY a.accepted_at DESC,a.document_id DESC LIMIT $4`, platform.Principal(c).Subject, at, id, limit+1)
	if err != nil {
		documentFailure(c)
		return
	}
	defer rows.Close()
	items := []historyItem{}
	for rows.Next() {
		var item historyItem
		var accepted time.Time
		if rows.Scan(&item.ID, &item.Kind, &item.Version, &item.Locale, &item.SHA256, &item.MaterialChange, &item.PublishedAt, &accepted, &item.Context) != nil {
			documentFailure(c)
			return
		}
		item.AcceptedAt = &accepted
		items = append(items, item)
	}
	if rows.Err() != nil {
		documentFailure(c)
		return
	}
	var next any
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		raw, _ := json.Marshal(historyCursor{Version: 1, At: *last.AcceptedAt, ID: last.ID})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	c.JSON(200, gin.H{"items": items, "next_cursor": next})
}
