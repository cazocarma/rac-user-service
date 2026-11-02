package httpapi

import (
	"net/http"

	"github.com/cazocarma/rac-platform/contentsignals"
	"github.com/gin-gonic/gin"
)

type publicText struct {
	field string
	text  string
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
