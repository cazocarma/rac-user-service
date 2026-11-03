package httpapi

import (
	"context"
	"errors"
	"testing"
	"time"

	platformidentity "github.com/cazocarma/rac-platform/identity"
	"github.com/cazocarma/rac-user-service/internal/config"
	"github.com/cazocarma/rac-user-service/internal/listings"
)

func TestListingPrerequisitesRecordWhatWasChecked(t *testing.T) {
	const subject = "6f1c3f6e-4a35-4c86-9c3b-0f6b0e1c2d3e"
	approved, reads := false, 0
	s := New(nil, config.Config{})
	s.identityGate = gateFunc(func(q platformidentity.Query) (platformidentity.Observation, error) {
		reads++
		if q.AccountID != subject || q.Purpose != platformidentity.CompaOnboarding {
			return platformidentity.Observation{}, errors.New("unexpected identity query")
		}
		return platformidentity.Observation{Query: q, Approved: approved, ObservedAt: time.Now()}, nil
	})
	check := s.ListingPrerequisites()
	// Disabled gates are reported as not evaluated, never as satisfied.
	if checked, err := check(context.Background(), nil, subject); err != nil || checked != (listings.Checked{}) || reads != 0 {
		t.Fatal("disabled gates evaluated or reported as checked", checked, err, reads)
	}
	t.Setenv("IDENTITY_ENFORCEMENT_ENABLED", "true")
	if _, err := check(context.Background(), nil, subject); !errors.Is(err, listings.ErrPrerequisites) || reads != 1 {
		t.Fatal("missing identity approved a listing", err)
	}
	approved = true
	if checked, err := check(context.Background(), nil, subject); err != nil || checked != (listings.Checked{Identity: true}) {
		t.Fatal("approved identity rejected", checked, err)
	}
	s.identityGate = gateFunc(func(platformidentity.Query) (platformidentity.Observation, error) {
		return platformidentity.Observation{}, errors.New("authority down")
	})
	if _, err := check(context.Background(), nil, subject); err == nil || errors.Is(err, listings.ErrPrerequisites) {
		t.Fatal("unavailable identity authority not reported as unavailable", err)
	}
}
