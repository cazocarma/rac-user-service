package contentsignals

import "context"

// ContainsPublicContact evaluates only the public contact policy. It does not
// load the proposed private lexicon or convert suspicion into a sanction.
// Callers must handle analysis errors before persisting public text. Private
// account contact fields and private messages must not use this policy.
func ContainsPublicContact(ctx context.Context, text string) (bool, error) {
	if len(text) > MaxInput {
		return false, ErrTooLarge
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	found := len(detectContact(text)) != 0
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return found, nil
}
