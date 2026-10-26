// Package standing defines account capabilities. Importing it alone does not
// secure an endpoint: callers must load authoritative state and recheck at commit.
package standing

import "context"

type Status string

const (
	Active     Status = "active"
	Restricted Status = "restricted"
	Suspended  Status = "suspended"
	Banned     Status = "banned"
)

type Capability string

// IsProtective classifies a capability; authentication and ownership checks
// remain mandatory. Other gates reuse this classification to preserve D02.
func IsProtective(capability Capability) bool { return protective(capability) }

// IsCommercial reports only known commercial capabilities. Unknown values
// must not become a protective bypass when another gate is added.
func IsCommercial(capability Capability) bool { return commercial(capability) }

const (
	PublishListing   Capability = "publish_listing"
	RequestBooking   Capability = "request_booking"
	AcceptBooking    Capability = "accept_booking"
	SendMessage      Capability = "send_message"
	WriteReview      Capability = "write_review"
	SubmitReport     Capability = "submit_report"
	Appeal           Capability = "appeal"
	AccessSafety     Capability = "access_safety"
	CancelOwnBooking Capability = "cancel_own_booking"
	RequestPrivacy   Capability = "request_privacy"
	RecoverAccount   Capability = "recover_account"
	AcceptDocuments  Capability = "accept_documents"
)

type Decision struct {
	Version uint64
	Allowed bool
}

// Authorizer must fail closed on error. Ownership and authentication remain the
// caller's responsibility, including for protective capabilities.
type Authorizer interface {
	Authorize(context.Context, string, Capability) (Decision, error)
}
