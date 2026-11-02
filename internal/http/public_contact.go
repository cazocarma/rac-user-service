package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/cazocarma/rac-platform/contentsignals"
	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
)

type publicText struct {
	field string
	text  string
}

// Signup display names are untrusted too. Revalidate the complete stored public
// profile under the same writer lock before either publication path proceeds.
// Login and protective account reads remain available even with an invalid name.
func lockedPublicProfile(c *gin.Context, ctx context.Context, tx *sql.Tx, subject string) (string, bool) {
	var id, name, biography string
	var interests pq.StringArray
	err := tx.QueryRowContext(ctx, `SELECT id::text,nombre,biografia,COALESCE(intereses,'{}'::text[]) FROM usuario WHERE keycloak_id=$1 FOR NO KEY UPDATE`, subject).Scan(&id, &name, &biography, &interests)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(409, gin.H{"error": "profile_required"})
		return "", false
	}
	if err != nil {
		c.JSON(503, gin.H{"error": "profile_unavailable"})
		return "", false
	}
	if rejectPublicContact(c, publicText{"nombre", name}, publicText{"biografia", biography}, publicText{"intereses", strings.Join(interests, " ")}) {
		return "", false
	}
	return id, true
}

// Reject before opening a write transaction. Never return source fragments,
// detector rule IDs or private account fields in this public response.
func rejectPublicContact(c *gin.Context, fields ...publicText) bool {
	for _, field := range fields {
		found, err := contentsignals.ContainsPublicContact(c.Request.Context(), field.text)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "content_check_unavailable"})
			return true
		}
		if found {
			c.JSON(http.StatusBadRequest, gin.H{"error": "public_contact_not_allowed", "field": field.field})
			return true
		}
	}
	return false
}
