package repo

// PublicStandingClause is applied before ordering/pagination, never by filtering
// an already paged result. Queries must bind the profile owner as usuario u.
// Disabled preview keeps legacy deployments independent of standing migrations.
func PublicStandingClause(enabled bool) string {
	if !enabled {
		return ""
	}
	return ` AND EXISTS (SELECT 1 FROM standing.account sa WHERE sa.subject_id=u.id
 AND sa.version>0 AND sa.status IN ('active','restricted')
 AND NOT EXISTS (SELECT 1 FROM standing.restriction sr WHERE sr.subject_id=sa.subject_id
 AND sr.capability='publish_listing' AND sr.starts_at<=statement_timestamp()
 AND (sr.ends_at IS NULL OR sr.ends_at>statement_timestamp()))) `
}
