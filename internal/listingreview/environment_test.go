package listingreview

import (
	"context"
	"database/sql"
	"testing"

	"github.com/cazocarma/rac-user-service/internal/listings"
)

func TestListingReviewEnvironmentIsExplicitAndSeparated(t *testing.T) {
	check := func(context.Context, *sql.Tx, string) (listings.Checked, error) { return listings.Checked{}, nil }
	for _, value := range []string{"", "false"} {
		t.Setenv("LISTING_REVIEW_ENABLED", value)
		if server, err := FromEnvironment(nil, check); server != nil || err != nil {
			t.Fatal("listing review listener enabled without opt-in", value, err)
		}
	}
	t.Setenv("LISTING_REVIEW_ENABLED", "yes")
	if _, err := FromEnvironment(nil, check); err == nil {
		t.Fatal("ambiguous activation flag accepted")
	}
	t.Setenv("LISTING_REVIEW_ENABLED", "true")
	const reader = "postgres://rac_listing_reader:x@postgres/rac?sslmode=disable"
	const corrector = "postgres://rac_listing_corrector:x@postgres/rac?sslmode=disable"
	for _, urls := range [][3]string{
		{"", corrector, "approver"},
		{reader, "", "approver"},
		{reader, corrector, ""},
		{reader, reader, "approver"},
		{reader, corrector, corrector},
		{reader, corrector, reader},
	} {
		t.Setenv("LISTING_REVIEW_READER_DATABASE_URL", urls[0])
		t.Setenv("LISTING_REVIEW_CORRECTOR_DATABASE_URL", urls[1])
		t.Setenv("LISTING_REVIEW_APPROVER_DATABASE_URL", urls[2])
		if server, err := FromEnvironment(nil, check); server != nil || err == nil {
			t.Fatal("listing review ingresses shared or missed a dedicated login", urls)
		}
	}
}
