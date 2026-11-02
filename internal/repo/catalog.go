package repo

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/lib/pq"
)

// ErrInvalidActivities rejects unknown, retired, unapproved, duplicated or
// excess activities. Nothing outside the closed catalog can be offered.
var ErrInvalidActivities = errors.New("invalid_activities")

var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,47}$`)

// CatalogPolicy decides which categories are offered. The seeded list is a
// proposal (D04): only dev/test serve proposed entries; elsewhere only
// approved ones. The per-compa maximum defaults to five.
type CatalogPolicy struct {
	AllowProposed bool
	MaxPerCompa   int
}

func CatalogFromEnvironment() CatalogPolicy {
	environment := os.Getenv("RAC_ENV")
	policy := CatalogPolicy{AllowProposed: environment == "dev" || environment == "test", MaxPerCompa: 5}
	if raw := os.Getenv("CATALOG_MAX_PER_COMPA"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 1 && value <= 12 {
			policy.MaxPerCompa = value
		}
	}
	return policy
}

// visibleCategory is the single SQL predicate for offered categories.
const visibleCategory = `c.status='active' AND (c.approval='approved' OR $%d)`

func visible(argument int) string {
	return strings.Replace(visibleCategory, "%d", strconv.Itoa(argument), 1)
}

type Category struct {
	Slug           string `json:"slug"`
	NameKey        string `json:"name_key"`
	DescriptionKey string `json:"description_key"`
	Setting        string `json:"setting"`
}

type Activity struct {
	Slug    string  `json:"slug"`
	NameKey string  `json:"name_key"`
	Note    *string `json:"nota,omitempty"`
}

type ActivityInput struct {
	Slug string `json:"slug"`
	Note string `json:"nota"`
}

func (r *Repo) ListCategories(ctx context.Context, policy CatalogPolicy) ([]Category, error) {
	rows, err := r.DB.QueryContext(ctx, `SELECT c.slug,c.name_key,c.description_key,c.setting FROM activity_categories c
 WHERE `+visible(1)+` ORDER BY c.sort,c.slug`, policy.AllowProposed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Category, 0)
	for rows.Next() {
		var c Category
		if err := rows.Scan(&c.Slug, &c.NameKey, &c.DescriptionKey, &c.Setting); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// NormalizeActivities validates the request shape before any storage access.
func NormalizeActivities(input []ActivityInput, policy CatalogPolicy) ([]ActivityInput, error) {
	if len(input) < 1 || len(input) > policy.MaxPerCompa {
		return nil, ErrInvalidActivities
	}
	seen := map[string]bool{}
	out := make([]ActivityInput, 0, len(input))
	for _, item := range input {
		item.Note = strings.TrimSpace(item.Note)
		if !slugPattern.MatchString(item.Slug) || seen[item.Slug] || utf8.RuneCountInString(item.Note) > 140 ||
			strings.IndexFunc(item.Note, unicode.IsControl) >= 0 {
			return nil, ErrInvalidActivities
		}
		seen[item.Slug] = true
		out = append(out, item)
	}
	return out, nil
}

// ReplaceActivities swaps a compa's activities inside the caller's
// transaction. Every slug must be an offered category.
func ReplaceActivities(ctx context.Context, tx *sql.Tx, compaID string, input []ActivityInput, policy CatalogPolicy) error {
	slugs := make([]string, len(input))
	for i, item := range input {
		slugs[i] = item.Slug
	}
	rows, err := tx.QueryContext(ctx, `SELECT c.slug,c.id::text FROM activity_categories c WHERE c.slug=ANY($2) AND `+visible(1),
		policy.AllowProposed, pq.Array(slugs))
	if err != nil {
		return err
	}
	ids := map[string]string{}
	for rows.Next() {
		var slug, id string
		if err := rows.Scan(&slug, &id); err != nil {
			rows.Close()
			return err
		}
		ids[slug] = id
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(ids) != len(input) {
		return ErrInvalidActivities
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM compa_activities WHERE compa_id=$1`, compaID); err != nil {
		return err
	}
	for _, item := range input {
		var note any
		if item.Note != "" {
			note = item.Note
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO compa_activities(compa_id,category_id,note) VALUES($1,$2,$3)`, compaID, ids[item.Slug], note); err != nil {
			return err
		}
	}
	return nil
}

// activitiesFor loads offered activities for the given compa profiles.
func (r *Repo) activitiesFor(ctx context.Context, compaIDs []string, policy CatalogPolicy) (map[string][]Activity, error) {
	out := map[string][]Activity{}
	if len(compaIDs) == 0 {
		return out, nil
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT a.compa_id::text,c.slug,c.name_key,a.note FROM compa_activities a
 JOIN activity_categories c ON c.id=a.category_id WHERE a.compa_id::text=ANY($2) AND `+visible(1)+` ORDER BY c.sort,c.slug`,
		policy.AllowProposed, pq.Array(compaIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var compa string
		var a Activity
		var note sql.NullString
		if err := rows.Scan(&compa, &a.Slug, &a.NameKey, &note); err != nil {
			return nil, err
		}
		if note.Valid {
			a.Note = &note.String
		}
		out[compa] = append(out[compa], a)
	}
	return out, rows.Err()
}

// offeredClause keeps compas without any offered activity out of every public
// read: catalog, detail and reviews share this visibility rule.
func offeredClause(argument int) string { return ` AND ` + offeredExists(argument) }

func offeredExists(argument int) string {
	return `EXISTS (SELECT FROM compa_activities oa JOIN activity_categories c ON c.id=oa.category_id
 WHERE oa.compa_id=cp.id AND ` + visible(argument) + `)`
}
